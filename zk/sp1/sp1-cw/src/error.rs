use std::fmt::{Display, Formatter};

use cosmwasm_std::StdError;

#[derive(Debug)]
pub enum ContractError {
    Std(StdError),

    Unauthorized {},

    SP1Verification(String),
}

impl Display for ContractError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
