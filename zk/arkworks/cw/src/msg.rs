use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::HexBinary;

#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum ExecuteMsg {
    PenumbraShieldedGraph {
        proof: HexBinary,
        public_inputs: HexBinary,
    },
    TestDecaf377Rdsa {},
    TestPoseidon377 {},
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {}
