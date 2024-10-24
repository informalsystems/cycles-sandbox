#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult};
// use cw2::set_contract_version;
use sp1_sdk::{ProverClient, SP1ProofWithPublicValues, SP1VerifyingKey};

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};

/*
// version info for migration info
const CONTRACT_NAME: &str = "crates.io:sp1-cw";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");
*/

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::VerifyProof {
            proof_bytes,
            verifying_key_bytes,
        } => {
            let client = ProverClient::new();

            let proof: SP1ProofWithPublicValues =
                bincode::deserialize(&proof_bytes).map_err(|e| {
                    ContractError::Std(StdError::parse_err(
                        "SP1ProofWithPublicValues",
                        e.to_string(),
                    ))
                })?;

            let vk: SP1VerifyingKey = bincode::deserialize(&verifying_key_bytes).map_err(|e| {
                ContractError::Std(StdError::parse_err("SP1VerifyingKey", e.to_string()))
            })?;

            client
                .verify(&proof, &vk)
                .map(|_| Response::new())
                .map_err(|e| ContractError::Std(StdError::generic_err(e.to_string())))
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, _msg: QueryMsg) -> StdResult<Binary> {
    unimplemented!()
}

#[cfg(test)]
mod tests {}
