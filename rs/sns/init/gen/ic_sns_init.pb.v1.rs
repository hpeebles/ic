/// This struct contains all the parameters necessary to initialize an SNS. All fields are optional
/// to avoid future candid compatibility problems. However, for the struct to be "valid", all fields
/// must be populated.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, Eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SnsInitPayload {
    /// Fee of a transaction.
    #[prost(uint64, optional, tag="1")]
    pub transaction_fee_e8s: ::core::option::Option<u64>,
    /// The name of the token issued by an SNS Ledger.
    /// This field has no default, a value must be provided by the user.
    /// Must be a string length between {} and {} characters
    ///
    /// Example: Bitcoin
    #[prost(string, optional, tag="2")]
    pub token_name: ::core::option::Option<::prost::alloc::string::String>,
    /// The symbol of the token issued by an SNS Ledger. This field has no
    /// default, a value must be provided by the user. Must be a string length
    /// between 3 and 10 characters
    #[prost(string, optional, tag="3")]
    pub token_symbol: ::core::option::Option<::prost::alloc::string::String>,
    /// Cost of making a proposal that doesnt pass.
    #[prost(uint64, optional, tag="4")]
    pub proposal_reject_cost_e8s: ::core::option::Option<u64>,
    /// The minimum amount a neuron needs to have staked.
    #[prost(uint64, optional, tag="5")]
    pub neuron_minimum_stake_e8s: ::core::option::Option<u64>,
    /// Amount targeted by the swap, if the amount is reached the swap is triggered. Must be at least
    /// min_participants * min_participant_icp_e8.
    #[prost(uint64, optional, tag="7")]
    pub max_icp_e8s: ::core::option::Option<u64>,
    /// Minimum number of participants for the swap to take place. Must be greater than zero.
    #[prost(uint32, optional, tag="8")]
    pub min_participants: ::core::option::Option<u32>,
    /// The minimum amount of icp that each buyer must contribute to participate.
    #[prost(uint64, optional, tag="9")]
    pub min_participant_icp_e8s: ::core::option::Option<u64>,
    /// The maximum amount of ICP that each buyer can contribute. Must be
    /// greater than or equal to `min_participant_icp_e8s` and less than
    /// or equal to `max_icp_e8s`. Can effectively be disabled by
    /// setting it to `max_icp_e8s`.
    #[prost(uint64, optional, tag="10")]
    pub max_participant_icp_e8s: ::core::option::Option<u64>,
    /// The total number of ICP that is required for this token swap to
    /// take place. This number divided by the number of SNS tokens being
    /// offered gives the seller's reserve price for the swap, i.e., the
    /// minimum number of ICP per SNS tokens that the seller of SNS
    /// tokens is willing to accept. If this amount is not achieved, the
    /// swap will be aborted (instead of committed) when the due date/time
    /// occurs. Must be smaller than or equal to `max_icp_e8s`.
    #[prost(uint64, optional, tag="11")]
    pub min_icp_e8s: ::core::option::Option<u64>,
    /// If the swap fails, control of the dapp canister(s) will be set to these
    /// principal IDs. In most use-cases, this would be the same as the original
    /// set of controller(s). Must not be empty.
    #[prost(string, repeated, tag="12")]
    pub fallback_controller_principal_ids: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// The initial tokens and neurons available at genesis will be distributed according
    /// to the strategy and configuration picked via the initial_token_distribution
    /// parameter.
    #[prost(oneof="sns_init_payload::InitialTokenDistribution", tags="6")]
    pub initial_token_distribution: ::core::option::Option<sns_init_payload::InitialTokenDistribution>,
}
/// Nested message and enum types in `SnsInitPayload`.
pub mod sns_init_payload {
    /// The initial tokens and neurons available at genesis will be distributed according
    /// to the strategy and configuration picked via the initial_token_distribution
    /// parameter.
    #[derive(candid::CandidType, candid::Deserialize, serde::Serialize, Eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum InitialTokenDistribution {
        /// See `FractionalDeveloperVotingPower`
        #[prost(message, tag="6")]
        FractionalDeveloperVotingPower(super::FractionalDeveloperVotingPower),
    }
}
/// The FractionalDeveloperVotingPower token distribution strategy configures
/// how tokens and neurons are distributed via four "buckets": developers,
/// treasury, swap, and airdrops. This strategy will distribute all developer tokens
/// at genesis in restricted neurons with an additional voting power
/// multiplier applied. This voting power multiplier is calculated as
/// `swap_distribution.initial_swap_amount_e8s / swap_distribution.total_e8s`.
/// As more of the swap funds are swapped in future rounds, the voting power
/// multiplier will approach 1.0. The following preconditions must be met for
/// it to be a valid distribution:
///    - developer_distribution.developer_neurons.stake_e8s.sum <= u64:MAX
///    - developer_neurons.developer_neurons.stake_e8s.sum <= swap_distribution.total_e8s
///    - airdrop_distribution.airdrop_neurons.stake_e8s.sum <= u64:MAX
///    - swap_distribution.initial_swap_amount_e8s > 0
///    - swap_distribution.initial_swap_amount_e8s <= swap_distribution.total_e8s
///    - swap_distribution.total_e8s >= developer_distribution.developer_neurons.stake_e8s.sum
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, Eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FractionalDeveloperVotingPower {
    /// The developer bucket.
    #[prost(message, optional, tag="1")]
    pub developer_distribution: ::core::option::Option<DeveloperDistribution>,
    /// The treasury bucket.
    #[prost(message, optional, tag="2")]
    pub treasury_distribution: ::core::option::Option<TreasuryDistribution>,
    /// The swap bucket.
    #[prost(message, optional, tag="3")]
    pub swap_distribution: ::core::option::Option<SwapDistribution>,
    /// The airdrop bucket.
    #[prost(message, optional, tag="4")]
    pub airdrop_distribution: ::core::option::Option<AirdropDistribution>,
}
/// The distributions awarded to developers at SNS genesis.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, Eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeveloperDistribution {
    /// List of `NeuronDistribution` that specify a Neuron controller and Neuron stake in e8s (10E-8 of a token).
    /// For each entry in the developer_neurons list, a neuron will be created with a voting multiplier applied
    /// (see `FractionalDeveloperVotingPower`) and will start in PreInitializationSwap mode.
    #[prost(message, repeated, tag="1")]
    pub developer_neurons: ::prost::alloc::vec::Vec<NeuronDistribution>,
}
/// The funds for the SNS' Treasury account on the SNS Ledger. These funds are
/// in the SNS Ledger at genesis, but unavailable until after the initial swap
/// has successfully completed.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, Eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TreasuryDistribution {
    /// The total token distribution denominated in e8s (10E-8 of a token) of the
    /// treasury bucket.
    #[prost(uint64, tag="1")]
    pub total_e8s: u64,
}
/// The funds for token swaps to decentralize an SNS. These funds are in the
/// SNS Ledger at genesis.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, Eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SwapDistribution {
    /// The total token distribution denominated in e8s (10E-8 of a token) of the
    /// swap bucket. All tokens used in initial_swap_amount_e8s will be
    /// deducted from total_e8s. The remaining tokens will be distributed to
    /// a subaccount of Governance for use in future token swaps.
    #[prost(uint64, tag="1")]
    pub total_e8s: u64,
    /// The initial number of tokens denominated in e8s (10E-8 of a token)
    /// deposited in the swap canister's account for the initial token swap.
    #[prost(uint64, tag="2")]
    pub initial_swap_amount_e8s: u64,
}
/// The distributions airdropped at SNS genesis.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, Eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AirdropDistribution {
    /// List of `NeuronDistribution` that specify a Neuron controller and Neuron stake in e8s
    /// (10E-8 of a token). For each entry in the airdrop_neurons list, a neuron will be
    /// created with NO voting multiplier applied and will start in PreInitializationSwap mode.
    #[prost(message, repeated, tag="1")]
    pub airdrop_neurons: ::prost::alloc::vec::Vec<NeuronDistribution>,
}
/// A tuple of values used to create a Neuron available at SNS genesis.
#[derive(candid::CandidType, candid::Deserialize, serde::Serialize, Eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NeuronDistribution {
    /// The initial `PrincipalId` given permissions on a neuron available at genesis.
    /// The permissions granted to the controller will be set to the SNS' configured
    /// `NervousSystemParameters.neuron_claimer_permissions`. This controller
    /// will be the first available `PrincipalId` to manage a neuron.
    #[prost(message, optional, tag="1")]
    pub controller: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// The stake denominated in e8s (10E-8 of a token) that the neuron will have
    /// at genesis. The `Neuron.cached_neuron_stake_e8s` in SNS Governance and the
    /// Neuron's account in the SNS Ledger will have this value.
    #[prost(uint64, tag="2")]
    pub stake_e8s: u64,
}
