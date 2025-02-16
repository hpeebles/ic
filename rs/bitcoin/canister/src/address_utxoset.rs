use crate::{state::UtxoSet, types::Storable, utxos::UtxosTrait};
use bitcoin::{Address, OutPoint, Transaction, TxOut};
use ic_btc_types::{Address as AddressStr, Height, Utxo};
use std::collections::{BTreeMap, BTreeSet};

/// A struct that tracks the UTXO set of a given address.
///
/// Given a reference to a full UTXO set, it is able to simulate adding
/// additional transactions and its impact on the UTXO set of `address`, which
/// is used for computing the UTXOs of an address at varying heights.
pub struct AddressUtxoSet<'a> {
    // The address to track the UTXOs of.
    address: String,

    // A reference to the (full) underlying UTXO set.
    full_utxo_set: &'a UtxoSet,

    // Added UTXOs that are not present in the underlying UTXO set indexed by
    // the encoded form of (`Height`, `OutPoint`).
    //
    // Note that we use the encoded form of (`Height`, `Outpoint`) to match with
    // the data that's stored in the `StableBtreeMap` and be able to have
    // consistent ordering between the two when combining the results for a
    // `get_utxos` response.
    added_utxos: BTreeMap<Vec<u8>, TxOut>,

    // Removed UTXOs that are still present in the underlying UTXO set.
    removed_utxos: BTreeMap<OutPoint, (TxOut, Height)>,
}

impl<'a> AddressUtxoSet<'a> {
    /// Initialize an `AddressUtxoSet` that tracks the UTXO set of `address`.
    pub fn new(address: String, full_utxo_set: &'a UtxoSet) -> Self {
        Self {
            address,
            full_utxo_set,
            removed_utxos: BTreeMap::new(),
            added_utxos: BTreeMap::new(),
        }
    }

    /// Inserts a transaction at the given height.
    pub fn insert_tx(&mut self, tx: &Transaction, height: Height) {
        self.remove_spent_txs(tx);
        self.insert_unspent_txs(tx, height);
    }

    // Iterates over transaction inputs and removes spent outputs.
    fn remove_spent_txs(&mut self, tx: &Transaction) {
        if tx.is_coin_base() {
            return;
        }

        let outpoint_to_height: BTreeMap<OutPoint, Height> = self
            .added_utxos
            .keys()
            .map(|x| {
                let (height, outpoint) = <(Height, OutPoint)>::from_bytes(x.clone());
                (outpoint, height)
            })
            .collect();

        for input in &tx.input {
            if let Some(height) = outpoint_to_height.get(&input.previous_output) {
                // Remove a UTXO that was previously added.
                self.added_utxos
                    .remove(&(*height, input.previous_output).to_bytes());
                return;
            }

            let (txout, height) = self
                .full_utxo_set
                .utxos
                .get(&input.previous_output)
                .unwrap_or_else(|| panic!("Cannot find outpoint: {}", &input.previous_output));

            // Remove it.
            let old_value = self
                .removed_utxos
                .insert(input.previous_output, (txout.clone(), height));
            assert_eq!(old_value, None, "Cannot remove an output twice");
        }
    }

    // Iterates over transaction outputs and adds unspents.
    fn insert_unspent_txs(&mut self, tx: &Transaction, height: Height) {
        for (vout, output) in tx.output.iter().enumerate() {
            if !(output.script_pubkey.is_provably_unspendable()) {
                // Insert the outpoint.
                //
                // NOTE: In theory we only need to store the UTXO here if it's owned
                // by the address we're interested in. However, storing everything
                // allows us to have stronger verification that all inputs/outputs
                // are being consumed as expected.
                assert!(
                    self.added_utxos
                        .insert(
                            (height, OutPoint::new(tx.txid(), vout as u32)).to_bytes(),
                            output.clone(),
                        )
                        .is_none(),
                    "Cannot insert same outpoint twice"
                );
            }
        }
    }

    pub fn into_vec(mut self, offset: Option<(Height, OutPoint)>) -> Vec<Utxo> {
        // Retrieve all the UTXOs of the address from the underlying UTXO set.
        let mut set: BTreeSet<_> = self
            .full_utxo_set
            .address_to_outpoints
            .range(self.address.to_bytes(), offset.map(|x| x.to_bytes()))
            .map(|(k, _)| {
                let (_, _, outpoint) = <(AddressStr, Height, OutPoint)>::from_bytes(k);
                let (txout, height) = self
                    .full_utxo_set
                    .utxos
                    .get(&outpoint)
                    .expect("outpoint must exist");

                ((height, outpoint).to_bytes(), txout)
            })
            .collect();

        // Include all the newly added UTXOs for that address that are "after" the optional offset.
        let added_utxos = match offset {
            Some(offset) => self.added_utxos.split_off(&offset.to_bytes()),
            None => self.added_utxos,
        };
        for (height_and_outpoint, txout) in added_utxos {
            if let Some(address) =
                Address::from_script(&txout.script_pubkey, self.full_utxo_set.network)
            {
                if address.to_string() == self.address {
                    assert!(
                        set.insert((height_and_outpoint, txout)),
                        "Cannot overwrite existing outpoint"
                    );
                }
            }
        }

        for (outpoint, (txout, height)) in self.removed_utxos {
            if let Some(address) =
                Address::from_script(&txout.script_pubkey, self.full_utxo_set.network)
            {
                if address.to_string() == self.address {
                    set.remove(&((height, outpoint).to_bytes(), txout));
                }
            }
        }

        set.into_iter()
            .map(|(height_and_outpoint, txout)| {
                let (height, outpoint) = <(Height, OutPoint)>::from_bytes(height_and_outpoint);
                Utxo {
                    outpoint: ic_btc_types::OutPoint {
                        txid: outpoint.txid.to_vec(),
                        vout: outpoint.vout,
                    },
                    value: txout.value,
                    height,
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bitcoin::secp256k1::rand::rngs::OsRng;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{Address, Network, PublicKey};
    use ic_btc_test_utils::TransactionBuilder;
    use ic_btc_types::OutPoint as PublicOutPoint;

    #[test]
    fn add_tx_to_empty_utxo() {
        let secp = Secp256k1::new();
        let mut rng = OsRng::new().unwrap();

        // Create some BTC addresses.
        let address_1 = Address::p2pkh(
            &PublicKey::new(secp.generate_keypair(&mut rng).1),
            Network::Bitcoin,
        );

        let utxo_set = UtxoSet::new(Network::Bitcoin);

        let mut address_utxo_set = AddressUtxoSet::new(address_1.to_string(), &utxo_set);

        // Create a genesis block where 1000 satoshis are given to address 1.
        let coinbase_tx = TransactionBuilder::coinbase()
            .with_output(&address_1, 1000)
            .build();

        address_utxo_set.insert_tx(&coinbase_tx, 0);

        // Address should have that data.
        assert_eq!(
            address_utxo_set.into_vec(None),
            vec![Utxo {
                outpoint: PublicOutPoint {
                    txid: coinbase_tx.txid().to_vec(),
                    vout: 0
                },
                value: 1000,
                height: 0
            }]
        );
    }

    #[test]
    fn add_tx_then_transfer() {
        let secp = Secp256k1::new();
        let mut rng = OsRng::new().unwrap();

        // Create some BTC addresses.
        let address_1 = Address::p2pkh(
            &PublicKey::new(secp.generate_keypair(&mut rng).1),
            Network::Bitcoin,
        );
        let address_2 = Address::p2pkh(
            &PublicKey::new(secp.generate_keypair(&mut rng).1),
            Network::Bitcoin,
        );

        let utxo_set = UtxoSet::new(Network::Bitcoin);

        let mut address_utxo_set = AddressUtxoSet::new(address_1.to_string(), &utxo_set);

        // Create a genesis block where 1000 satoshis are given to address 1.
        let coinbase_tx = TransactionBuilder::coinbase()
            .with_output(&address_1, 1000)
            .build();

        address_utxo_set.insert_tx(&coinbase_tx, 0);

        // Extend block 0 with block 1 that spends the 1000 satoshis and gives them to address 2.
        let tx = TransactionBuilder::new()
            .with_input(bitcoin::OutPoint::new(coinbase_tx.txid(), 0))
            .with_output(&address_2, 1000)
            .build();

        address_utxo_set.insert_tx(&tx, 1);

        // Address should have that data.
        assert_eq!(address_utxo_set.into_vec(None), vec![]);

        let mut address_2_utxo_set = AddressUtxoSet::new(address_2.to_string(), &utxo_set);
        address_2_utxo_set.insert_tx(&coinbase_tx, 0);
        address_2_utxo_set.insert_tx(&tx, 1);

        assert_eq!(
            address_2_utxo_set.into_vec(None),
            vec![Utxo {
                outpoint: PublicOutPoint {
                    txid: tx.txid().to_vec(),
                    vout: 0
                },
                value: 1000,
                height: 1
            }]
        );
    }

    #[test]
    #[should_panic]
    fn insert_same_tx_twice() {
        let secp = Secp256k1::new();
        let mut rng = OsRng::new().unwrap();

        // Create some BTC addresses.
        let address_1 = Address::p2pkh(
            &PublicKey::new(secp.generate_keypair(&mut rng).1),
            Network::Bitcoin,
        );

        let utxo_set = UtxoSet::new(Network::Bitcoin);

        let mut address_utxo_set = AddressUtxoSet::new(address_1.to_string(), &utxo_set);

        // Create a genesis block where 1000 satoshis are given to address 1.
        let coinbase_tx = TransactionBuilder::coinbase()
            .with_output(&address_1, 1000)
            .build();

        address_utxo_set.insert_tx(&coinbase_tx, 0);

        // This should panic, as we already inserted that tx.
        address_utxo_set.insert_tx(&coinbase_tx, 0);
    }
}
