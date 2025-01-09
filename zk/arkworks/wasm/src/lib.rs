use ark_serialize::CanonicalSerialize;
use wasm_bindgen::prelude::*;
use ark_groth16::ProvingKey;
use decaf377::Fq;
use rand::rngs::OsRng;
use penumbra_shielded_pool::Note;
use ark_std::io::{Read, Write};

mod output;
mod nullifier;

use output::{OutputProof, OutputProofPrivate, OutputProofPublic};




#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub struct ProverState {
    proving_key: ProvingKey<decaf377::Bls12_377>,
}

#[wasm_bindgen]
impl ProverState {

    #[wasm_bindgen]
    pub fn create_output_proof(
        &self,
        note_bytes: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        let mut rng = OsRng;
        let blinding_r = Fq::rand(&mut rng);
        let blinding_s = Fq::rand(&mut rng);

        let note = Note::try_from(note_bytes)
            .map_err(|e| JsError::new(&format!("Failed to deserialize note: {}", e)))?;

        let public = OutputProofPublic {
            note_commitment: note.commit(),
        };
        let private = OutputProofPrivate { note };

        let proof = OutputProof::prove(
            blinding_r,
            blinding_s,
            &self.proving_key,
            public,
            private,
        )
        .map_err(|e| JsError::new(&format!("Failed to create proof: {}", e)))?;

        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes)
            .map_err(|e| JsError::new(&format!("Failed to serialize proof: {}", e)))?;

        Ok(proof_bytes)
    }
}