#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    Binary, Deps, DepsMut, Env, HashFunction, MessageInfo, Response, StdResult,
    BLS12_381_G1_GENERATOR,
};
use hex_literal::hex;

use crate::error::ContractError;
use crate::groth16::{Frame, Groth16Verifier};
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::ContractError::SP1Verification;

enum CryptoMode {
    Precompile,
    Raw,
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
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::VerifyProof {
            proof,
            public_inputs,
            vk_hash,
            vk,
        } => Groth16Verifier::verify(&proof, &public_inputs, &vk_hash, &vk)
            .map(|verified| {
                Response::new()
                    .add_attribute("verification", if verified { "passed" } else { "failed" })
            })
            .map_err(|e| SP1Verification(e.to_string())),
        ExecuteMsg::VerifyBls12PairingEquality {} => {
            let verified = test_pairing_equality(deps, CryptoMode::Precompile);

            Ok(Response::new()
                .add_attribute("verification", if verified { "passed" } else { "failed" }))
        }
        ExecuteMsg::VerifyBls12PairingEqualityRaw {} => {
            let verified = test_pairing_equality(deps, CryptoMode::Raw);

            Ok(Response::new()
                .add_attribute("verification", if verified { "passed" } else { "failed" }))
        }
        ExecuteMsg::VerifyProofFrame {
            proof,
            public_inputs,
            vk_hash,
            vk,
            frame,
        } => Groth16Verifier::verify_frame(
            &proof,
            &public_inputs,
            &vk_hash,
            &vk,
            Frame::from_u8(frame),
        )
        .map(|verified| {
            Response::new()
                .add_attribute("verification", if verified { "passed" } else { "failed" })
        })
        .map_err(|e| SP1Verification(e.to_string())),
    }
}

fn test_pairing_equality(deps: DepsMut, mode: CryptoMode) -> bool {
    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    let ps = hex!("a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79ab301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f");
    let qs: Vec<u8> = [
        hex!("0000000000000000000000000000000000000000000000000000000000000000"),
        hex!("5656565656565656565656565656565656565656565656565656565656565656"),
        hex!("abababababababababababababababababababababababababababababababab"),
    ]
    .into_iter()
    .flat_map(|msg| {
        deps.api
            .bls12_381_hash_to_g2(HashFunction::Sha256, &msg, dst)
            .unwrap()
    })
    .collect();
    let s = hex!("9104e74b9dfd3ad502f25d6a5ef57db0ed7d9a0e00f3500586d8ce44231212542fcfaf87840539b398bf07626705cf1105d246ca1062c6c2e1a53029a0f790ed5e3cb1f52f8234dc5144c45fc847c0cd37a92d68e7c5ba7c648a8a339f171244");

    match mode {
        CryptoMode::Precompile => deps
            .api
            .bls12_381_pairing_equality(&ps, &qs, &BLS12_381_G1_GENERATOR, &s)
            .unwrap(),
        CryptoMode::Raw => {
            cosmwasm_crypto::bls12_381_pairing_equality(&ps, &qs, &BLS12_381_G1_GENERATOR, &s)
                .unwrap()
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, _msg: QueryMsg) -> StdResult<Binary> {
    unimplemented!()
}

#[cfg(test)]
mod tests {}
