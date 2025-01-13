use base64::prelude::*;
use std::str::FromStr;

use anyhow::Result;
use ark_groth16::r1cs_to_qap::LibsnarkReduction;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use decaf377::{Bls12_377, Fq};
use decaf377_fmd as fmd;
use decaf377_ka as ka;

use ark_ff::ToConstraintField;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey};
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef};
use ark_snark::SNARK;
use penumbra_keys::{keys::Diversifier, Address};
use penumbra_proto::{penumbra::core::component::shielded_pool::v1 as pb, DomainType};
use penumbra_tct::r1cs::StateCommitmentVar;

use penumbra_asset::Value;
use penumbra_proof_params::{DummyWitness, VerifyingKeyExt, GROTH16_PROOF_LENGTH_BYTES};
use penumbra_shielded_pool::{note::StateCommitment, Rseed};

use crate::note::{r1cs::NoteVar, Note};

/// The public input for an [`OutputProof`].
#[derive(Clone, Debug)]
pub struct OutputProofPublic {
    /// A hiding commitment to the note.
    pub note_commitment: StateCommitment,
}

/// The private input for an [`OutputProof`].
#[derive(Clone, Debug)]
pub struct OutputProofPrivate {
    /// The note being created.
    pub note: Note,
}

#[cfg(test)]
fn check_satisfaction(public: &OutputProofPublic, private: &OutputProofPrivate) -> Result<()> {
    if private.note.diversified_generator() == decaf377::Element::default() {
        anyhow::bail!("diversified generator is identity");
    }

    let note_commitment = private.note.commit();
    if note_commitment != public.note_commitment {
        anyhow::bail!("note commitment did not match public input");
    }

    Ok(())
}

#[cfg(test)]
fn check_circuit_satisfaction(
    public: OutputProofPublic,
    private: OutputProofPrivate,
) -> Result<()> {
    use ark_relations::r1cs::{self, ConstraintSystem};

    let cs = ConstraintSystem::new_ref();
    let circuit = OutputCircuit { public, private };
    cs.set_optimization_goal(r1cs::OptimizationGoal::Constraints);
    circuit
        .generate_constraints(cs.clone())
        .expect("can generate constraints from circuit");
    cs.finalize();
    if !cs.is_satisfied()? {
        anyhow::bail!("constraints are not satisfied");
    }
    Ok(())
}

/// Public:
/// * ncm (note commitment)
///
/// Witnesses:
/// * g_d (point)
/// * pk_d (point)
/// * v (u128 value plus asset ID (scalar))
/// * nblind (Fq)
#[derive(Clone, Debug)]
pub struct OutputCircuit {
    public: OutputProofPublic,
    private: OutputProofPrivate,
}

impl OutputCircuit {
    fn new(public: OutputProofPublic, private: OutputProofPrivate) -> Self {
        Self { public, private }
    }
}

impl ConstraintSynthesizer<Fq> for OutputCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fq>) -> ark_relations::r1cs::Result<()> {
        // Witnesses
        // Note: In the allocation of the address on `NoteVar`, we check the diversified base is not identity.
        let note_var = NoteVar::new_witness(cs.clone(), || Ok(self.private.note.clone()))?;

        // Public inputs
        let claimed_note_commitment =
            StateCommitmentVar::new_input(cs.clone(), || Ok(self.public.note_commitment))?;

        // Note commitment integrity
        let note_commitment = note_var.commit()?;
        note_commitment.enforce_equal(&claimed_note_commitment)?;

        Ok(())
    }
}

impl DummyWitness for OutputCircuit {
    fn with_dummy_witness() -> Self {
        let diversifier_bytes = [1u8; 16];
        let pk_d_bytes = decaf377::Element::GENERATOR.vartime_compress().0;
        let clue_key_bytes = [1; 32];
        let diversifier = Diversifier(diversifier_bytes);
        let address = Address::from_components(
            diversifier,
            ka::Public(pk_d_bytes),
            fmd::ClueKey(clue_key_bytes),
        )
        .expect("generated 1 address");
        let note = Note::from_parts(
            address,
            Value::from_str("1upenumbra").expect("valid value"),
            Rseed([1u8; 32]),
        )
        .expect("can make a note");

        let public = OutputProofPublic {
            note_commitment: note.commit(),
        };
        let private = OutputProofPrivate { note };
        OutputCircuit { public, private }
    }
}

#[derive(Clone, Debug)]
pub struct OutputProof([u8; GROTH16_PROOF_LENGTH_BYTES]);

impl OutputProof {
    #![allow(clippy::too_many_arguments)]
    /// Generate an [`OutputProof`] given the proving key, public inputs,
    /// witness data, and two random elements `blinding_r` and `blinding_s`.
    pub fn prove(
        blinding_r: Fq,
        blinding_s: Fq,
        pk: &ProvingKey<Bls12_377>,
        public: OutputProofPublic,
        private: OutputProofPrivate,
    ) -> anyhow::Result<Self> {
        let circuit = OutputCircuit::new(public, private);
        let proof = Groth16::<Bls12_377, LibsnarkReduction>::create_proof_with_reduction(
            circuit, pk, blinding_r, blinding_s,
        )
        .map_err(|err| anyhow::anyhow!(err))?;
        let mut proof_bytes = [0u8; GROTH16_PROOF_LENGTH_BYTES];
        Proof::serialize_compressed(&proof, &mut proof_bytes[..]).expect("can serialize Proof");
        Ok(Self(proof_bytes))
    }

    /// Called to verify the proof using the provided public inputs.
    ///
    /// The public inputs are:
    /// * note commitment of the new note,
    // For debugging proof verification failures:
    // to check that the proof data and verification keys are consistent.
    #[tracing::instrument(level="debug", skip(self, vk), fields(self = ?BASE64_STANDARD.encode(self.clone().encode_to_vec()), vk = ?vk.debug_id()))]
    pub fn verify(
        &self,
        vk: &PreparedVerifyingKey<Bls12_377>,
        public: OutputProofPublic,
    ) -> anyhow::Result<()> {
        let proof =
            Proof::deserialize_compressed_unchecked(&self.0[..]).map_err(|e| anyhow::anyhow!(e))?;

        let mut public_inputs = Vec::new();
        public_inputs.extend(
            public
                .note_commitment
                .0
                .to_field_elements()
                .ok_or_else(|| anyhow::anyhow!("note commitment is not a valid field element"))?,
        );

        tracing::trace!(?public_inputs);
        let start = std::time::Instant::now();
        let proof_result = Groth16::<Bls12_377, LibsnarkReduction>::verify_with_processed_vk(
            vk,
            public_inputs.as_slice(),
            &proof,
        )
        .map_err(|err| anyhow::anyhow!(err))?;
        tracing::debug!(?proof_result, elapsed = ?start.elapsed());
        proof_result
            .then_some(())
            .ok_or_else(|| anyhow::anyhow!("output proof did not verify"))
    }
}

impl DomainType for OutputProof {
    type Proto = pb::ZkOutputProof;
}

impl From<OutputProof> for pb::ZkOutputProof {
    fn from(proof: OutputProof) -> Self {
        pb::ZkOutputProof {
            inner: proof.0.to_vec(),
        }
    }
}

impl TryFrom<pb::ZkOutputProof> for OutputProof {
    type Error = anyhow::Error;

    fn try_from(proto: pb::ZkOutputProof) -> Result<Self, Self::Error> {
        Ok(OutputProof(proto.inner[..].try_into()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::note::{commitment, Note};

    use decaf377::Fq;
    use penumbra_asset::{asset, Value};
    use penumbra_keys::keys::{Bip44Path, SeedPhrase, SpendKey};
    use penumbra_num::Amount;
    use proptest::prelude::*;

    fn fq_strategy() -> BoxedStrategy<Fq> {
        any::<[u8; 32]>()
            .prop_map(|bytes| Fq::from_le_bytes_mod_order(&bytes[..]))
            .boxed()
    }

    prop_compose! {
        fn arb_valid_output_statement()(seed_phrase_randomness in any::<[u8; 32]>(), rseed_randomness in any::<[u8; 32]>(), amount in any::<u64>(), asset_id64 in any::<u64>(), address_index in any::<u32>()) -> (OutputProofPublic, OutputProofPrivate) {
            let seed_phrase = SeedPhrase::from_randomness(&seed_phrase_randomness);
            let sk_recipient = SpendKey::from_seed_phrase_bip44(seed_phrase, &Bip44Path::new(0));
            let fvk_recipient = sk_recipient.full_viewing_key();
            let ivk_recipient = fvk_recipient.incoming();
            let (dest, _dtk_d) = ivk_recipient.payment_address(address_index.into());

            let value_to_send = Value {
                amount: Amount::from(amount),
                asset_id: asset::Id(Fq::from(asset_id64)),
            };
            let note = Note::from_parts(
                dest,
                value_to_send,
                Rseed(rseed_randomness),
            ).expect("should be able to create note");
            let note_commitment = note.commit();

            let public = OutputProofPublic { note_commitment };
            let private = OutputProofPrivate { note };

            (public, private)
        }
    }

    proptest! {
        #[test]
        fn output_proof_happy_path((public, private) in arb_valid_output_statement()) {
            assert!(check_satisfaction(&public, &private).is_ok());
            assert!(check_circuit_satisfaction(public, private).is_ok());
        }
    }

    prop_compose! {
        // This strategy generates an output statement, but then replaces the note commitment
        // with one generated using an invalid note blinding factor.
        fn arb_invalid_output_note_commitment_integrity()(seed_phrase_randomness in any::<[u8; 32]>(), rseed_randomness in any::<[u8; 32]>(), amount in any::<u64>(), asset_id64 in any::<u64>(), address_index in any::<u32>(), incorrect_note_blinding in fq_strategy()) -> (OutputProofPublic, OutputProofPrivate) {
            let seed_phrase = SeedPhrase::from_randomness(&seed_phrase_randomness);
            let sk_recipient = SpendKey::from_seed_phrase_bip44(seed_phrase, &Bip44Path::new(0));
            let fvk_recipient = sk_recipient.full_viewing_key();
            let ivk_recipient = fvk_recipient.incoming();
            let (dest, _dtk_d) = ivk_recipient.payment_address(address_index.into());

            let value_to_send = Value {
                amount: Amount::from(amount),
                asset_id: asset::Id(Fq::from(asset_id64)),
            };
            let note = Note::from_parts(
                dest,
                value_to_send,
                Rseed(rseed_randomness),
            ).expect("should be able to create note");

            let incorrect_note_commitment = commitment(
                incorrect_note_blinding,
                value_to_send,
                note.diversified_generator(),
                note.transmission_key_s(),
                note.clue_key(),
            );

            let bad_public = OutputProofPublic { note_commitment: incorrect_note_commitment };
            let private = OutputProofPrivate { note };

            (bad_public, private)
        }
    }

    proptest! {
        #[test]
        /// Check that the `OutputCircuit` is not satisfied when the note commitment is invalid.
        fn output_proof_verification_fails_note_commitment_integrity((public, private) in arb_invalid_output_note_commitment_integrity()) {
            assert!(check_satisfaction(&public, &private).is_err());
            assert!(check_circuit_satisfaction(public, private).is_err());
        }
    }
}
