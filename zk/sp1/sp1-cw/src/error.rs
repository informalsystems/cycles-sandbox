use cosmwasm_std::StdError;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum ContractError {
    Std(StdError),

    Unauthorized {},
    // Add any other custom errors you like here.
    // Look at https://docs.rs/thiserror/1.0.21/thiserror/ for details.
}

impl Display for ContractError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
