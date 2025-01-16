use crate::Request;
use candid::Principal;
use pocket_ic::nonblocking::PocketIc;
use thiserror::Error;

use crate::CallCanisters;

#[derive(Error, Debug)]
pub enum PocketIcCallError {
    #[error("pocket_ic error: {0}")]
    PocketIc(pocket_ic::RejectResponse),
    #[error("canister request could not be encoded: {0}")]
    CandidEncode(candid::Error),
    #[error("canister did not respond with the expected response type: {0}")]
    CandidDecode(candid::Error),
}

impl crate::sealed::Sealed for PocketIc {}

impl CallCanisters for PocketIc {
    type Error = PocketIcCallError;
    async fn call<R: Request>(
        &self,
        canister_id: impl Into<Principal> + Send,
        request: R,
    ) -> Result<R::Response, Self::Error> {
        let canister_id = canister_id.into();
        let request_bytes = request.payload().map_err(PocketIcCallError::CandidEncode)?;
        let response = if request.update() {
            self.update_call(
                canister_id,
                Principal::anonymous(),
                request.method(),
                request_bytes,
            )
            .await
        } else {
            self.query_call(
                canister_id,
                Principal::anonymous(),
                request.method(),
                request_bytes,
            )
            .await
        }
        .map_err(PocketIcCallError::PocketIc)?;

        candid::decode_one(response.as_slice()).map_err(PocketIcCallError::CandidDecode)
    }
}
