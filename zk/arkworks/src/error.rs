use cosmwasm_std::StdError;
use std::fmt::Display;

#[derive(Debug)]
pub enum ContractError {
    Std(StdError),

    Unauthorized {},
    // Add any other custom errors you like here.
    // Look at https://docs.rs/thiserror/1.0.21/thiserror/ for details.
}

impl From<StdError> for ContractError {
    fn from(error: StdError) -> Self {
        ContractError::Std(error)
    }
}

impl Display for ContractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
