#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Binary, Deps, DepsMut, Env, HexBinary, MessageInfo, Response, StdResult};
use cw2::set_contract_version;

use crate::error::{ContractError, Groth16VerificationError};
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{State, STATE};

use ark_groth16::r1cs_to_qap::LibsnarkReduction;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use decaf377::{Bls12_377, Fq};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:zk-cw";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

const GROTH16_PROOF_LENGTH_BYTES: usize = 192;
const OUTPUT_PROOF_VERIFYING_KEY: &[u8] = include_bytes!("../data/output_vk.param");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let state = State {
        owner: info.sender.clone(),
    };
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    STATE.save(deps.storage, &state)?;

    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("owner", info.sender))
}

pub fn verify(
    proof_bytes: [u8; GROTH16_PROOF_LENGTH_BYTES],
    public_inputs_bytes: &[u8],
    verifying_key: &PreparedVerifyingKey<Bls12_377>,
) -> Result<bool, Groth16VerificationError> {
    let proof = Proof::deserialize_compressed_unchecked(&proof_bytes[0..])
        .map_err(Groth16VerificationError::ProofDeserialization)?;

    let public_inputs = Vec::<Fq>::deserialize_compressed_unchecked(public_inputs_bytes)
        .map_err(Groth16VerificationError::PublicInputsDeserialization)?;

    let verified = Groth16::<Bls12_377, LibsnarkReduction>::verify_with_processed_vk(
        verifying_key,
        public_inputs.as_slice(),
        &proof,
    )?;

    Ok(verified)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::PenumbraShieldedGraph {
            proof,
            public_inputs,
        } => {
            let vk = VerifyingKey::deserialize_uncompressed_unchecked(OUTPUT_PROOF_VERIFYING_KEY)
                .expect("can deserialize VerifyingKey");
            let verified = verify(proof.to_array()?, public_inputs.as_slice(), &vk.into())?;
            Ok(Response::new()
                .add_attribute("verification", if verified { "passed" } else { "failed" }))
        }
        ExecuteMsg::TestDecaf377Rdsa {} => {
            use decaf377_rdsa::*;

            let sk = SigningKey::<SpendAuth>::try_from(
                HexBinary::from_hex(
                    "4f75b1d5d7eefae2e606de2b4daa25d5dd2e3f54f3bed7d34a27b88cbd1d7b00",
                )
                .unwrap()
                .to_array::<32>()
                .unwrap(),
            )
            .unwrap();
            let sig_bytes = HexBinary::from_hex("a8aa8a85a1deb25d4836e153520535e123069b01fe056f327ac8fb98da91f00dc8847101bb5c820fea5a0777ba4528f2d7b860fef7a89bfd8e4152ae83935003").unwrap().to_array::<64>().unwrap();
            let pk_bytes: [u8; 32] = VerificationKey::from(&sk).into();

            // Deserialize and verify the signature.
            let msg = b"Hello!";
            let sig: Signature<SpendAuth> = sig_bytes.into();
            assert!(VerificationKey::try_from(pk_bytes)
                .and_then(|pk| pk.verify(msg, &sig))
                .is_ok());

            Ok(Response::new())
        }
        ExecuteMsg::TestPoseidon377 {} => {
            use core::str::FromStr;

            use poseidon377::*;

            let domain_sep = Fq::from_le_bytes_mod_order(b"Penumbra_TestVec");

            let input = Fq::from_str(
                "7553885614632219548127688026174585776320152166623257619763178041781456016062",
            )
            .unwrap();
            let output = hash_1(&domain_sep, input);

            let expected_output = Fq::from_str(
                "2337838243217876174544784248400816541933405738836087430664765452605435675740",
            )
            .unwrap();

            assert_eq!(output, expected_output);

            Ok(Response::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::HexBinary;

    use super::*;

    #[test]
    fn test_verify() {
        let vk: PreparedVerifyingKey<Bls12_377> =
            VerifyingKey::deserialize_uncompressed_unchecked(OUTPUT_PROOF_VERIFYING_KEY)
                .expect("can deserialize VerifyingKey")
                .into();
        let proof = HexBinary::from_hex("08f791e07165a2b9b4f98732f4326013ffc59286586b22aae0fe0bdff0b6150b631e24fc21765cfad22c7d220ded820154022fdfc194d523e4e3828836b919b722774c77e37ccd0937edb5928d69840ff1a50d7ff8f2f34db24f1f12970824018016d04fcae7714294952a65dc53dda104751ec26e02427e77b3971ac4fdca3e1c20117e51a6fa564a83a6b79fe60f81a040075383626f25b17561ddc9195526e49280ae11bcd5e920af23d6204b48c2e2f55d772cc1661d9e969411ca671a00").unwrap();
        let public_inputs = HexBinary::from_hex("02000000000000006502c5281a48ea6499dfdd0b1e2571be402556d07195fa5429845d14e91632057ad10727b3d29e1c273348f53bd6b4d83a59d89ee0a8eebfb4432423afe05206").unwrap();
        let verified = verify(proof.to_array().unwrap(), public_inputs.as_slice(), &vk).unwrap();
        assert!(verified);
    }

    #[test]
    fn test_signature_verification() {
        use decaf377_rdsa::*;
        // use rand::thread_rng;
        //
        let msg = b"Hello!";
        //
        // // Generate a secret key and sign the message
        // let sk = SigningKey::<SpendAuth>::new(thread_rng());
        // println!("{}", HexBinary::from(&sk.to_bytes()));
        //
        // let sig = sk.sign(thread_rng(), msg);
        //
        // // Types can be converted to raw byte arrays using From/Into
        // let sig_bytes: [u8; 64] = sig.into();
        // println!("{}", HexBinary::from(&sig_bytes));

        let sk = SigningKey::<SpendAuth>::try_from(
            HexBinary::from_hex("4f75b1d5d7eefae2e606de2b4daa25d5dd2e3f54f3bed7d34a27b88cbd1d7b00")
                .unwrap()
                .to_array::<32>()
                .unwrap(),
        )
        .unwrap();
        let sig_bytes = HexBinary::from_hex("a8aa8a85a1deb25d4836e153520535e123069b01fe056f327ac8fb98da91f00dc8847101bb5c820fea5a0777ba4528f2d7b860fef7a89bfd8e4152ae83935003").unwrap().to_array::<64>().unwrap();
        let pk_bytes: [u8; 32] = VerificationKey::from(&sk).into();

        // Deserialize and verify the signature.
        let sig: Signature<SpendAuth> = sig_bytes.into();
        assert!(VerificationKey::try_from(pk_bytes)
            .and_then(|pk| pk.verify(msg, &sig))
            .is_ok());
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, _msg: QueryMsg) -> StdResult<Binary> {
    todo!()
}
