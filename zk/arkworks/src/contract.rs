#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Binary, Deps, DepsMut, Env, HexBinary, MessageInfo, Response, StdResult};
use cw2::set_contract_version;

use penumbra_asset::balance::Commitment as BalanceCommitment;
use penumbra_proof_params::OUTPUT_PROOF_VERIFICATION_KEY;
use penumbra_shielded_graph::{note::StateCommitment, output::OutputProofPublic, OutputProof};

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{State, STATE};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:zk-cw";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

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

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::PenumbraShieldedGraph {} => {
            let proof_bytes = HexBinary::from_hex("e4f570fe3fa4e8f58b3ce7f23a9f7539d3a8821f80b901b1a5c4e15902086ef10ce1b7f011afcf95c44a49895fb0a5016b1c5ed814c5a613e3f95b10c9866e6748f532b4242cd5a84ae70256483159571c6f92f5cb37e8e10794e52edb96b1006c58d7f052121560c3f4ec4de60a888f9f79d65d1ca8e595979d9f11246800c0131d949d911f54a6d4ae3ce41b586a00138ce174a9fc6c7edf383c2ed61c3ca7d3a7463fd11faf6a9a9c96c5bd5b35c8a6e2a8a7bae8d6880e5e9b52d5eef780").unwrap();
            OutputProof(proof_bytes.to_array().unwrap())
                .verify(
                    &OUTPUT_PROOF_VERIFICATION_KEY,
                    OutputProofPublic {
                        balance_commitment: BalanceCommitment(
                            HexBinary::from_hex(
                                "5e6bb5f7916d40312e5467df3614be78151fec8fc592aa75916411d37fdd0d05",
                            )
                            .unwrap()
                            .to_array::<32>()
                            .unwrap()
                            .try_into()
                            .unwrap(),
                        ),
                        note_commitment: StateCommitment::parse_hex(
                            "d97ebb8abcab7b3c702969222a5c59aab6f921588dcb41fb992af55f61363101",
                        )
                        .unwrap(),
                    },
                )
                .unwrap();
            Ok(Response::new())
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(_deps: Deps, _env: Env, _msg: QueryMsg) -> StdResult<Binary> {
    todo!()
}
