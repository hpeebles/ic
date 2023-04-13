"""
Common dependencies for system-tests.
"""

DEPENDENCIES = [
    "//packages/icrc-ledger-agent:icrc_ledger_agent",
    "//packages/icrc-ledger-types:icrc_ledger_types",
    "//rs/artifact_pool",
    "//rs/backup",
    "//rs/bitcoin/ckbtc/agent",
    "//rs/bitcoin/ckbtc/kyt",
    "//rs/bitcoin/ckbtc/minter",
    "//rs/boundary_node/certificate_issuance/certificate_orchestrator_interface",
    "//rs/canister_client",
    "//rs/canister_client/sender",
    "//rs/certification",
    "//rs/config",
    "//rs/constants",
    "//rs/crypto",
    "//rs/crypto/sha",
    "//rs/crypto/test_utils/reproducible_rng",
    "//rs/crypto/tree_hash",
    "//rs/cup_explorer",
    "//rs/http_utils",
    "//rs/interfaces",
    "//rs/interfaces/registry",
    "//rs/nervous_system/common",
    "//rs/nervous_system/common/test_keys",
    "//rs/nervous_system/root",
    "//rs/nns/cmc",
    "//rs/nns/common",
    "//rs/nns/constants",
    "//rs/nns/governance",
    "//rs/nns/gtc",
    "//rs/nns/handlers/lifeline",
    "//rs/nns/handlers/root",
    "//rs/nns/init",
    "//rs/nns/sns-wasm",
    "//rs/nns/test_utils",
    "//rs/phantom_newtype",
    "//rs/prep",
    "//rs/protobuf",
    "//rs/recovery",
    "//rs/registry/canister",
    "//rs/registry/client",
    "//rs/registry/helpers",
    "//rs/registry/keys",
    "//rs/registry/local_registry",
    "//rs/registry/local_store",
    "//rs/registry/local_store/artifacts",
    "//rs/registry/nns_data_provider",
    "//rs/registry/provisional_whitelist",
    "//rs/registry/routing_table",
    "//rs/registry/regedit",
    "//rs/registry/subnet_features",
    "//rs/registry/subnet_type",
    "//rs/registry/transport",
    "//rs/replay",
    "//rs/rosetta-api",
    "//rs/rosetta-api/icrc1",
    "//rs/rosetta-api/icrc1/ledger",
    "//rs/rosetta-api/icp_ledger",
    "//rs/rosetta-api/ledger_canister_blocks_synchronizer/test_utils",
    "//rs/rosetta-api/ledger_core",
    "//rs/rosetta-api/test_utils",
    "//rs/rust_canisters/canister_test",
    "//rs/rust_canisters/dfn_candid",
    "//rs/rust_canisters/dfn_core",
    "//rs/rust_canisters/dfn_protobuf",
    "//rs/rust_canisters/on_wire",
    "//rs/rust_canisters/proxy_canister:lib",
    "//rs/rust_canisters/xnet_test",
    "//rs/sns/init",
    "//rs/sns/swap",
    "//rs/sns/root",
    "//rs/sns/governance",
    "//rs/tests/test_canisters/message:lib",
    "//rs/test_utilities",
    "//rs/test_utilities/identity",
    "//rs/tree_deserializer",
    "//rs/types/base_types",
    "//rs/types/ic00_types",
    "//rs/types/types",
    "//rs/types/types_test_utils",
    "//rs/universal_canister/lib",
    "//rs/utils",
    "@crate_index//:anyhow",
    "@crate_index//:assert-json-diff",
    "@crate_index//:assert_matches",
    "@crate_index//:base64",
    "@crate_index//:bincode",
    "@crate_index//:bitcoincore-rpc",
    "@crate_index//:candid",
    "@crate_index//:chrono",
    "@crate_index//:clap",
    "@crate_index//:crossbeam-channel",
    "@crate_index//:crossbeam-utils",
    "@crate_index//:flate2",
    "@crate_index//:futures",
    "@crate_index//:garcon",
    "@crate_index//:hex",
    "@crate_index//:humantime",
    "@crate_index//:hyper",
    "@crate_index//:hyper-rustls",
    "@crate_index//:hyper-tls",
    "@crate_index//:ic-agent",
    "@crate_index//:ic-btc-interface",
    "@crate_index//:ic-cdk",
    "@crate_index//:ic-utils",
    "@crate_index//:itertools",
    "@crate_index//:json5",
    "@crate_index//:k256",
    "@crate_index//:lazy_static",
    "@crate_index//:leb128",
    "@crate_index//:maplit",
    "@crate_index//:nix",
    "@crate_index//:num_cpus",
    "@crate_index//:openssh-keys",
    "@crate_index//:openssl",
    "@crate_index//:pem",
    "@crate_index//:proptest",
    "@crate_index//:prost",
    "@crate_index//:quickcheck",
    "@crate_index//:rand_0_8_4",
    "@crate_index//:rand_chacha_0_3_1",
    "@crate_index//:rayon",
    "@crate_index//:regex",
    "@crate_index//:reqwest",
    "@crate_index//:ring",
    "@crate_index//:rustls",
    "@crate_index//:serde",
    "@crate_index//:serde_bytes",
    "@crate_index//:serde_cbor",
    "@crate_index//:serde_json",
    "@crate_index//:serde_millis",
    "@crate_index//:slog",
    "@crate_index//:slog-async",
    "@crate_index//:slog-term",
    "@crate_index//:ssh2",
    "@crate_index//:tempfile",
    "@crate_index//:thiserror",
    "@crate_index//:tokio",
    "@crate_index//:url",
    "@crate_index//:walkdir",
    "@crate_index//:wat",
]

MACRO_DEPENDENCIES = [
    "@crate_index//:async-recursion",
    "@crate_index//:async-trait",
]

GUESTOS_RUNTIME_DEPS = [
    "//ic-os/guestos/envs/dev:hash_and_upload_disk-img",
    "//ic-os/guestos/envs/dev:hash_and_upload_update-img",
    "//ic-os/guestos:scripts/build-bootstrap-config-image.sh",
]

NNS_CANISTER_RUNTIME_DEPS = ["//rs/tests:nns-canisters"]

MAINNET_NNS_CANISTER_RUNTIME_DEPS = ["//rs/tests:mainnet-nns-canisters"]

UNIVERSAL_VM_RUNTIME_DEPS = [
    "//rs/tests:create-universal-vm-config-image.sh",
]

GRAFANA_RUNTIME_DEPS = UNIVERSAL_VM_RUNTIME_DEPS + [
    "//rs/tests:grafana_dashboards",
]

BOUNDARY_NODE_GUESTOS_RUNTIME_DEPS = [
    "//ic-os/boundary-guestos/envs/dev:hash_and_upload_disk-img",
    "//ic-os/boundary-guestos:scripts/build-bootstrap-config-image.sh",
]

BOUNDARY_NODE_GUESTOS_SEV_RUNTIME_DEPS = [
    "//ic-os/boundary-guestos/envs/dev-sev:hash_and_upload_disk-img",
]

COUNTER_CANISTER_RUNTIME_DEPS = ["//rs/tests:src/counter.wat"]

GUESTOS_MALICIOUS_RUNTIME_DEPS = [
    "//ic-os/guestos/envs/dev-malicious:hash_and_upload_disk-img",
    "//ic-os/guestos/envs/dev-malicious:hash_and_upload_update-img",
    "//ic-os/guestos:scripts/build-bootstrap-config-image.sh",
]

CANISTER_HTTP_RUNTIME_DEPS = [
    "//rs/tests:http_uvm_config_image",
]

XNET_TEST_CANISTER_RUNTIME_DEPS = ["//rs/rust_canisters/xnet_test:xnet-test-canister"]
