use crate::common::local_replica;
use crate::common::local_replica::test_identity;
use ic_agent::Identity;
use ic_base_types::PrincipalId;
use ic_icrc1_ledger::InitArgs;
use ic_icrc_rosetta::common::storage::storage_client::StorageClient;
use ic_icrc_rosetta::common::utils::unit_test_utils::strategies::transfer_args_with_sender;
use ic_icrc_rosetta::common::utils::unit_test_utils::DEFAULT_TRANSFER_FEE;
use ic_icrc_rosetta::ledger_blocks_synchronization::blocks_synchronizer::{self, blocks_verifier};
use ic_ledger_canister_core::archive::ArchiveOptions;
use icrc_ledger_agent::Icrc1Agent;
use icrc_ledger_types::icrc1::account::Account;
use lazy_static::lazy_static;
use proptest::prelude::*;
use std::sync::Arc;
use tokio::runtime::Runtime;

lazy_static! {
    pub static ref TEST_ACCOUNT: Account = test_identity().sender().unwrap().into();
    pub static ref MAX_NUM_GENERATED_BLOCKS: usize = 20;
    pub static ref NUM_TEST_CASES: u32 = 5;
}

fn check_storage_validity(storage_client: Arc<StorageClient>, highest_index: u64) {
    // Get the tip of the blockchain from the storage client
    let tip_block = storage_client.get_block_with_highest_block_idx().unwrap();

    // Get the genesis block from the blockchain
    let genesis_block = storage_client.get_block_with_lowest_block_idx().unwrap();

    // Get the the entire blockchain
    let blocks_stored = storage_client
        .get_blocks_by_index_range(0, highest_index)
        .unwrap();

    // The index of the tip of the chain should be the number of generated blocks
    assert_eq!(tip_block.unwrap().index, highest_index.clone());

    // The index of the genesis block should be 0
    assert_eq!(genesis_block.unwrap().index, 0);

    // The number of stored blocks should be the number of generated blocks generated in total plus the genesis block
    assert_eq!(blocks_stored.len() as u64, highest_index + 1);

    // Make sure the blocks that are stored are valid
    assert!(blocks_verifier::is_valid_blockchain(
        &blocks_stored,
        &blocks_stored.last().unwrap().block_hash
    ));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(*NUM_TEST_CASES))]
    #[test]
    fn test_simple_start_of_synchronizing_blocks(transfer_args_batch1 in transfer_args_with_sender(*MAX_NUM_GENERATED_BLOCKS, *TEST_ACCOUNT),transfer_args_batch2 in transfer_args_with_sender(*MAX_NUM_GENERATED_BLOCKS, *TEST_ACCOUNT)) {
    // Create a tokio environment to conduct async calls
    let rt = Runtime::new().unwrap();

    // Wrap async calls in a blocking Block
    rt.block_on(async {

    // Spin up a local replica
    let replica_context = local_replica::start_new_local_replica().await;

    // Deploy an icrc ledger canister
    let icrc_ledger_canister_id =
        local_replica::deploy_icrc_ledger_with_custom_args(&replica_context,
            InitArgs {
                minting_account: *TEST_ACCOUNT,
                fee_collector_account: None,
                initial_balances: vec![(*TEST_ACCOUNT,1_000_000_000_000)],
                transfer_fee: DEFAULT_TRANSFER_FEE.get_e8s(),
                token_name: "Test Token".to_owned(),
                token_symbol: "TT".to_owned(),
                metadata: vec![],
                archive_options: ArchiveOptions {
                    trigger_threshold: 10_000,
                    num_blocks_to_archive: 10_000,
                    node_max_memory_size_bytes: None,
                    max_message_size_bytes: None,
                    controller_id: PrincipalId::new_user_test_id(100),
                    cycles_for_archive_creation: None,
                    max_transactions_per_response: None,
                },
            }).await;

    // Create a testing agent
    let agent = Arc::new(Icrc1Agent {
        agent: local_replica::get_testing_agent(&replica_context).await,
        ledger_canister_id: icrc_ledger_canister_id.into(),
    });


    // Create some blocks to be fetched later
    for transfer_arg in transfer_args_batch1.iter() {
        agent.transfer(transfer_arg.clone()).await.unwrap().unwrap();
    }

    // Create the storage client where blocks will be stored
    let storage_client = Arc::new(StorageClient::new_in_memory().unwrap());

    // Start the synching process
    // Conduct a full sync from the tip of the blockchain to genesis block
    blocks_synchronizer::start_synching_blocks(agent.clone(), storage_client.clone(),2).await.unwrap();

    // Check that the full sync of all blocks generated by the first batch of blocks is valid
    check_storage_validity(storage_client.clone(),transfer_args_batch1.len() as u64);

    // Create some more blocks to be fetched later
    for transfer_arg in transfer_args_batch2.iter() {
        agent.transfer(transfer_arg.clone()).await.unwrap().unwrap();
    }

    // Sync between the tip of the chain and the stored blocks
    // The blocksynchronizer now sync the blocks between the current tip of the chain and the most recently stored block
    blocks_synchronizer::sync_from_the_tip(agent.clone(), storage_client.clone(),2).await.unwrap();

    // Check that the sync of all blocks generated by the second batch of blocks is valid
    check_storage_validity(storage_client.clone(),(transfer_args_batch1.len()+transfer_args_batch2.len()) as u64);


    // If we do another synchronization where there are no new blocks the synchronizer should be able to handle that
    blocks_synchronizer::start_synching_blocks(agent.clone(), storage_client.clone(),2).await.unwrap();

    // Storage should still be valid
    check_storage_validity(storage_client.clone(),(transfer_args_batch1.len()+transfer_args_batch2.len()) as u64);
        });

    }

    #[test]
    fn test_fetching_from_archive(transfer_args in transfer_args_with_sender(*MAX_NUM_GENERATED_BLOCKS, *TEST_ACCOUNT)) {
    // Create a tokio environment to conduct async calls
    let rt = Runtime::new().unwrap();

    // Wrap async calls in a blocking Block
    rt.block_on(async {

    // Spin up a local replica
    let replica_context = local_replica::start_new_local_replica().await;

    // Deploy an icrc ledger canister and make sure an archive is created
    let icrc_ledger_canister_id =
    local_replica::deploy_icrc_ledger_with_custom_args(&replica_context,
        InitArgs {
            minting_account: *TEST_ACCOUNT,
            fee_collector_account: None,
            initial_balances: vec![(*TEST_ACCOUNT,1_000_000_000_000)],
            transfer_fee: DEFAULT_TRANSFER_FEE.get_e8s(),
            token_name: "Test Token".to_owned(),
            token_symbol: "TT".to_owned(),
            metadata: vec![],
            archive_options: ArchiveOptions {
                // Create archive after every ten blocks
                trigger_threshold: 10,
                num_blocks_to_archive: 5,
                node_max_memory_size_bytes: None,
                max_message_size_bytes: None,
                controller_id: PrincipalId::new_user_test_id(100),
                cycles_for_archive_creation: None,
                max_transactions_per_response: None,
            },
        }).await;

    // Create a testing agent
    let agent = Arc::new(Icrc1Agent {
        agent: local_replica::get_testing_agent(&replica_context).await,
        ledger_canister_id: icrc_ledger_canister_id.into(),
    });


    // Create some blocks to be fetched later
    // An archive is created after 10 blocks
    for transfer_arg in transfer_args.iter() {
        agent.transfer(transfer_arg.clone()).await.unwrap().unwrap();
    }

    // Create the storage client where blocks will be stored
    let storage_client = Arc::new(StorageClient::new_in_memory().unwrap());

    // Start the synching process
    // Conduct a full sync from the tip of the blockchain to genesis block
    // Fetched blocks from the ledger and the archive
    blocks_synchronizer::start_synching_blocks(agent.clone(), storage_client.clone(),10).await.unwrap();

    // Check that the full sync of all blocks generated is valid
    check_storage_validity(storage_client.clone(),transfer_args.len() as u64);

    });
}
}
