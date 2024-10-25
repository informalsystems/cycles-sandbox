use std::borrow::Borrow;

#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult};
use itertools::Itertools;
use p3_field::PrimeField32;
use serde::{Deserialize, Serialize};
use sp1_core_machine::io::SP1Stdin;
use sp1_primitives::io::SP1PublicValues;
use sp1_prover::{
    components::DefaultProverComponents, CoreSC, SP1CoreProofData, SP1Prover, SP1VerifyingKey,
};
use sp1_stark::{air::PublicValues, ShardProof, Word};

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};

/// A proof generated with SP1, bundled together with stdin, public values, and the SP1 version.
#[derive(Clone, Serialize, Deserialize)]
pub struct SP1ProofWithPublicValues {
    pub proof: Vec<ShardProof<CoreSC>>,
    pub stdin: SP1Stdin,
    pub public_values: SP1PublicValues,
    pub sp1_version: String,
}

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
            let client = SP1Prover::<DefaultProverComponents>::new();

            let proof_bundle: SP1ProofWithPublicValues = bincode::deserialize(&proof_bytes)
                .map_err(|e| {
                    ContractError::Std(StdError::parse_err(
                        "SP1ProofWithPublicValues",
                        e.to_string(),
                    ))
                })?;

            let vk: SP1VerifyingKey = bincode::deserialize(&verifying_key_bytes).map_err(|e| {
                ContractError::Std(StdError::parse_err("SP1VerifyingKey", e.to_string()))
            })?;

            let proof = proof_bundle.proof;
            let public_values: &PublicValues<Word<_>, _> =
                proof.last().unwrap().public_values.as_slice().borrow();

            // Get the committed value digest bytes.
            let committed_value_digest_bytes = public_values
                .committed_value_digest
                .iter()
                .flat_map(|w| w.0.iter().map(|x| x.as_canonical_u32() as u8))
                .collect_vec();

            // Make sure the committed value digest matches the public values hash.
            for (a, b) in committed_value_digest_bytes
                .iter()
                .zip_eq(proof_bundle.public_values.hash())
            {
                if *a != b {
                    return Err(ContractError::SP1Verification);
                }
            }

            // Verify the core proof.
            client
                .verify(&SP1CoreProofData(proof.clone()), &vk)
                .map(|_| Response::default())
                .map_err(|_| ContractError::SP1Verification)
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, _msg: QueryMsg) -> StdResult<Binary> {
    unimplemented!()
}

#[cfg(test)]
mod tests {}
