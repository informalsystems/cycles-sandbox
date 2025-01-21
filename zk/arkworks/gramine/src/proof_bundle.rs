use ark_ff::ToConstraintField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use decaf377::Fq;
use penumbra_proof_params::GROTH16_PROOF_LENGTH_BYTES;
use penumbra_proto::core::component::shielded_pool::v1::ZkOutputProof;
use penumbra_shielded_pool::output::{OutputProof, OutputProofPublic};

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Groth16ProofBundle {
    pub proof: [u8; GROTH16_PROOF_LENGTH_BYTES],
    pub public_inputs: Vec<Fq>,
}

impl Groth16ProofBundle {
    pub fn new_from_output_proof(
        proof: OutputProof,
        proof_public: OutputProofPublic,
    ) -> Option<Self> {
        let proof = {
            let proof_bytes = ZkOutputProof::from(proof).inner;
            proof_bytes.try_into().ok()?
        };

        let mut public_inputs = Vec::new();
        public_inputs.extend(proof_public.note_commitment.0.to_field_elements()?);
        public_inputs.extend(proof_public.balance_commitment.0.to_field_elements()?);

        Some(Self {
            proof,
            public_inputs,
        })
    }
}
