/// All essential state of an SNS root canister.
///
/// When canister_init is called in the SNS root canister, it is expected that a
/// serialized version of this was passed via ic_ic00_types::InstallCodeArgs::args,
/// which can be retrieved by the canister via dfn_core::api::arg_data().
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SnsRootCanister {
    /// Required.
    ///
    /// The SNS root canister is supposed to be able to control this canister.  The
    /// governance canister sends the SNS root canister change_governance_canister
    /// update method calls (and possibly other things).
    #[prost(message, optional, tag="1")]
    pub governance_canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// Required.
    ///
    /// The SNS Ledger canister ID
    #[prost(message, optional, tag="2")]
    pub ledger_canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// Required.
    ///
    /// The swap canister ID.
    #[prost(message, optional, tag="4")]
    pub swap_canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
    /// Dapp canister IDs.
    #[prost(message, repeated, tag="3")]
    pub dapp_canister_ids: ::prost::alloc::vec::Vec<::ic_base_types::PrincipalId>,
}
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegisterDappCanisterRequest {
    #[prost(message, optional, tag="1")]
    pub canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
}
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegisterDappCanisterResponse {
}
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetDappControllersRequest {
    #[prost(message, repeated, tag="1")]
    pub controller_principal_ids: ::prost::alloc::vec::Vec<::ic_base_types::PrincipalId>,
}
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetDappControllersResponse {
    #[prost(message, repeated, tag="1")]
    pub failed_updates: ::prost::alloc::vec::Vec<set_dapp_controllers_response::FailedUpdate>,
}
/// Nested message and enum types in `SetDappControllersResponse`.
pub mod set_dapp_controllers_response {
    #[derive(candid::CandidType, candid::Deserialize)]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct FailedUpdate {
        #[prost(message, optional, tag="1")]
        pub dapp_canister_id: ::core::option::Option<::ic_base_types::PrincipalId>,
        #[prost(message, optional, tag="2")]
        pub err: ::core::option::Option<super::CanisterCallError>,
    }
}
#[derive(candid::CandidType, candid::Deserialize)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanisterCallError {
    #[prost(int32, optional, tag="1")]
    pub code: ::core::option::Option<i32>,
    #[prost(string, tag="2")]
    pub description: ::prost::alloc::string::String,
}
