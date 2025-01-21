use std::fmt::Display;

use ark_relations::r1cs::SynthesisError;
use ark_serialize::SerializationError;
use cosmwasm_std::StdError;

#[derive(Debug)]
pub enum ContractError {
    Std(StdError),
    Groth16Verification(Groth16VerificationError),
    Unauthorized {},
    // Add any other custom errors you like here.
    // Look at https://docs.rs/thiserror/1.0.21/thiserror/ for details.
}

impl From<StdError> for ContractError {
    fn from(error: StdError) -> Self {
        ContractError::Std(error)
    }
}

impl From<Groth16VerificationError> for ContractError {
    fn from(error: Groth16VerificationError) -> Self {
        ContractError::Groth16Verification(error)
    }
}

impl Display for ContractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug)]
pub enum Groth16VerificationError {
    ProofDeserialization(SerializationError),
    PublicInputsDeserialization(SerializationError),
    VerificationSynthesis(SynthesisError),
}

impl From<SynthesisError> for Groth16VerificationError {
    fn from(error: SynthesisError) -> Self {
        Groth16VerificationError::VerificationSynthesis(error)
    }
}
