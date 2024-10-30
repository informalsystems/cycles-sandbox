use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Binary;

#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum ExecuteMsg {
    VerifyProof {
        proof: Binary,
        public_inputs: Binary,
        vk_hash: String,
        vk: Binary,
    },
    VerifyBls12PairingEquality {},
    VerifyBls12PairingEqualityRaw {},
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {}
