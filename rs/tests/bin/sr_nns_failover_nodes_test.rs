#[rustfmt::skip]

use anyhow::Result;

use ic_tests::driver::group::SystemTestGroup;
use ic_tests::orchestrator::subnet_recovery_nns_failover::{setup, test};
use ic_tests::systest;

fn main() -> Result<()> {
    SystemTestGroup::new()
        .with_setup(setup)
        .add_test(systest!(test))
        .execute_from_args()?;
    Ok(())
}
