use cosmwasm_std::StdError;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum ContractError {
    Std(StdError),

    Unauthorized {},

    SP1Verification,
}

impl Display for ContractError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
