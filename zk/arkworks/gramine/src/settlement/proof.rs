use std::cmp::Ordering;
use std::str::FromStr;

use anyhow::Result;
use ark_ff::ToConstraintField;
use ark_groth16::r1cs_to_qap::LibsnarkReduction;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey};
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use base64::prelude::*;
use decaf377::{Bls12_377, Fq};
use decaf377_fmd as fmd;
use decaf377_ka as ka;
use penumbra_asset::{Value, ValueVar};
use penumbra_keys::{keys::Diversifier, Address};
use penumbra_num::{Amount, AmountVar};
use penumbra_proof_params::{DummyWitness, VerifyingKeyExt, GROTH16_PROOF_LENGTH_BYTES};
use penumbra_proto::{penumbra::core::component::shielded_pool::v1 as pb, DomainType};
use penumbra_shielded_pool::{note, Note, Rseed};
use penumbra_tct::r1cs::StateCommitmentVar;

use crate::nullifier::{Nullifier, NullifierVar};

/// The public input for an [`SettlementProof`].
#[derive(Clone, Debug)]
pub struct SettlementProofPublic {
    /// A hiding commitment to output notes.
    pub output_notes_commitments: Vec<note::StateCommitment>,
    /// Nullifiers for input notes.
    pub nullifiers: Vec<Nullifier>,
}

/// The private input for an [`SettlementProof`].
#[derive(Clone, Debug)]
pub struct SettlementProofPrivate {
    /// The output notes being created.
    pub output_notes: Vec<Note>,
    /// The input notes being spent.
    pub input_notes: Vec<Note>,
    /// Setoff amount for this cycle.
    pub setoff_amount: Amount,
}

#[cfg(test)]
fn check_satisfaction(
    public: &SettlementProofPublic,
    private: &SettlementProofPrivate,
) -> Result<()> {
    for (note_commitment, note) in public
        .output_notes_commitments
        .iter()
        .zip(private.output_notes.iter())
    {
        if note.diversified_generator() == decaf377::Element::default() {
            anyhow::bail!("diversified generator is identity");
        }

        if note_commitment != &note.commit() {
            anyhow::bail!("note commitment did not match public input");
        }
    }

    for (nullifier, note) in public.nullifiers.iter().zip(private.input_notes.iter()) {
        if nullifier != &Nullifier::derive(note) {
            anyhow::bail!("nullifier did not match public input");
        }
    }

    anyhow::ensure!(
        private.setoff_amount > Amount::zero(),
        "non-positive setoff amount"
    );

    for input_note in &private.input_notes {
        anyhow::ensure!(
            input_note.amount() >= private.setoff_amount,
            "note amount is less than setoff amount"
        );
    }

    let mut expected_output_notes = vec![];
    for note in &private.input_notes {
        let note = {
            let remainder = note.amount() - private.setoff_amount;
            let new_value = Value {
                amount: remainder,
                asset_id: note.asset_id(),
            };
            Note::from_parts(note.address(), new_value, note.rseed())?
        };
        expected_output_notes.push(note.commit());
    }
    anyhow::ensure!(
        expected_output_notes >= public.output_notes_commitments,
        "expected output notes do not match claimed"
    );

    Ok(())
}

#[cfg(test)]
fn check_circuit_satisfaction(
    public: SettlementProofPublic,
    private: SettlementProofPrivate,
) -> Result<()> {
    use ark_relations::r1cs::{self, ConstraintSystem};

    let cs = ConstraintSystem::new_ref();
    let circuit = SettlementCircuit { public, private };
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

#[derive(Clone, Debug)]
pub struct SettlementCircuit {
    public: SettlementProofPublic,
    private: SettlementProofPrivate,
}

impl SettlementCircuit {
    fn new(public: SettlementProofPublic, private: SettlementProofPrivate) -> Self {
        Self { public, private }
    }
}

impl ConstraintSynthesizer<Fq> for SettlementCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fq>) -> ark_relations::r1cs::Result<()> {
        for (note_commitment, note) in self
            .public
            .output_notes_commitments
            .iter()
            .zip(self.private.output_notes.iter())
        {
            // Witnesses
            // Note: In the allocation of the address on `NoteVar`, we check the diversified base is not identity.
            let note_var = note::NoteVar::new_witness(cs.clone(), || Ok(note.clone()))?;

            // Public inputs
            let claimed_note_commitment =
                StateCommitmentVar::new_input(cs.clone(), || Ok(note_commitment))?;

            // Note commitment integrity
            let note_commitment = note_var.commit()?;
            note_commitment.enforce_equal(&claimed_note_commitment)?;
        }

        for (nullifier, note) in self
            .public
            .nullifiers
            .iter()
            .zip(self.private.input_notes.iter())
        {
            // Witnesses
            // Note: In the allocation of the address on `NoteVar`, we check the diversified base is not identity.
            let note_var = note::NoteVar::new_witness(cs.clone(), || Ok(note.clone()))?;

            // Public inputs
            let claimed_nullifier_var = NullifierVar::new_input(cs.clone(), || Ok(nullifier))?;

            let nullifier_var = NullifierVar::derive(&note_var)?;
            nullifier_var.enforce_equal(&claimed_nullifier_var)?;
        }

        // let address_var = |n: &Note| AddressVar::new_witness(cs.clone(), || Ok(n.address()));
        // for notes in self.private.input_notes.windows(2) {
        //     let curr = address_var(&notes[0])?;
        //     let next = address_var(&notes[1])?;
        //     curr.enforce_equal(&next)?;
        // }
        // let first = self.private.input_notes.first().map(address_var).ok_or_else(||SynthesisError::Unsatisfiable)??;
        // let last = self.private.input_notes.last().map(address_var).ok_or_else(||SynthesisError::Unsatisfiable)??;
        // first.enforce_equal(&last)?;

        // Do we need to check there are >1 input notes?

        // setoff_amount > 0
        let value_var = |n: &Note| ValueVar::new_witness(cs.clone(), || Ok(n.value()));
        let setoff_var = AmountVar::new_witness(cs.clone(), || Ok(self.private.setoff_amount))?;
        let zero_var = AmountVar::new_witness(cs.clone(), || Ok(Amount::zero()))?;
        setoff_var
            .amount
            .enforce_cmp(&zero_var.amount, Ordering::Greater, false)?;

        // min_amount >= setoff_amount
        for note in &self.private.input_notes {
            let value_var = value_var(note)?;
            value_var
                .amount
                .amount
                .enforce_cmp(&setoff_var.amount, Ordering::Greater, true)?
        }

        let mut expected_output_notes = vec![];
        for note in self.private.input_notes {
            let note_var = {
                let remainder = note.amount() - self.private.setoff_amount;
                let new_value = Value {
                    amount: remainder,
                    asset_id: note.asset_id(),
                };
                let note = Note::from_parts(note.address(), new_value, note.rseed())
                    .map_err(|_| SynthesisError::Unsatisfiable)?;
                note::NoteVar::new_witness(cs.clone(), || Ok(note.clone()))?
            };
            expected_output_notes.push(note_var.commit()?);
        }
        for (expected, claimed) in expected_output_notes
            .iter()
            .zip(self.public.output_notes_commitments.iter())
        {
            let claimed = StateCommitmentVar::new_input(cs.clone(), || Ok(claimed))?;
            expected.enforce_equal(&claimed)?;
        }

        Ok(())
    }
}

impl DummyWitness for SettlementCircuit {
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

        let public = SettlementProofPublic {
            output_notes_commitments: vec![note.commit()],
            nullifiers: vec![Nullifier::derive(&note)],
        };
        let private = SettlementProofPrivate {
            output_notes: vec![note.clone()],
            input_notes: vec![note],
            setoff_amount: Amount::zero(),
        };
        SettlementCircuit { public, private }
    }
}

#[derive(Clone, Debug)]
pub struct SettlementProof([u8; GROTH16_PROOF_LENGTH_BYTES]);

impl SettlementProof {
    #![allow(clippy::too_many_arguments)]
    /// Generate an [`SettlementProof`] given the proving key, public inputs,
    /// witness data, and two random elements `blinding_r` and `blinding_s`.
    pub fn prove(
        blinding_r: Fq,
        blinding_s: Fq,
        pk: &ProvingKey<Bls12_377>,
        public: SettlementProofPublic,
        private: SettlementProofPrivate,
    ) -> anyhow::Result<Self> {
        let circuit = SettlementCircuit::new(public, private);
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
        public: SettlementProofPublic,
    ) -> anyhow::Result<()> {
        let proof =
            Proof::deserialize_compressed_unchecked(&self.0[..]).map_err(|e| anyhow::anyhow!(e))?;

        let mut public_inputs: Vec<Fq> = Vec::new();
        public_inputs.extend(
            public
                .output_notes_commitments
                .into_iter()
                .map(|c| c.0.to_field_elements())
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| anyhow::anyhow!("note commitment is not a valid field element"))?
                .iter()
                .flatten(),
        );
        public_inputs.extend(
            public
                .nullifiers
                .into_iter()
                .map(|c| c.0.to_field_elements())
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| anyhow::anyhow!("nullifier is not a valid field element"))?
                .iter()
                .flatten(),
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
            .ok_or_else(|| anyhow::anyhow!("settlement proof did not verify"))
    }
}

impl DomainType for SettlementProof {
    type Proto = pb::ZkOutputProof;
}

impl From<SettlementProof> for pb::ZkOutputProof {
    fn from(proof: SettlementProof) -> Self {
        pb::ZkOutputProof {
            inner: proof.0.to_vec(),
        }
    }
}

impl TryFrom<pb::ZkOutputProof> for SettlementProof {
    type Error = anyhow::Error;

    fn try_from(proto: pb::ZkOutputProof) -> Result<Self, Self::Error> {
        Ok(SettlementProof(proto.inner[..].try_into()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use decaf377::Fq;
    use penumbra_asset::{asset, Value};
    use penumbra_keys::keys::{Bip44Path, SeedPhrase, SpendKey};
    use penumbra_num::Amount;
    use penumbra_shielded_pool::{note, Note};
    use proptest::prelude::*;

    fn fq_strategy() -> BoxedStrategy<Fq> {
        any::<[u8; 32]>()
            .prop_map(|bytes| Fq::from_le_bytes_mod_order(&bytes[..]))
            .boxed()
    }

    prop_compose! {
        fn arb_valid_settlement_statement()(seed_phrase_randomness in any::<[u8; 32]>(), rseed_randomness in any::<[u8; 32]>(), amount in 2u64.., asset_id64 in any::<u64>(), address_index in any::<u32>()) -> (SettlementProofPublic, SettlementProofPrivate) {
            let seed_phrase = SeedPhrase::from_randomness(&seed_phrase_randomness);
            let sk_recipient = SpendKey::from_seed_phrase_bip44(seed_phrase, &Bip44Path::new(0));
            let fvk_recipient = sk_recipient.full_viewing_key();
            let ivk_recipient = fvk_recipient.incoming();
            let (dest, _dtk_d) = ivk_recipient.payment_address(address_index.into());

            let value_to_send = Value {
                amount: Amount::from(amount),
                asset_id: asset::Id(Fq::from(asset_id64)),
            };
            let input_note = Note::from_parts(
                dest.clone(),
                value_to_send,
                Rseed(rseed_randomness),
            ).expect("should be able to create note");
            let input_note_nullifier = Nullifier::derive(&input_note);

            let setoff_amount = amount/2;
            let value_reduced = Value {
                amount: Amount::from(amount - setoff_amount),
                asset_id: asset::Id(Fq::from(asset_id64)),
            };
            let output_note = Note::from_parts(
                dest,
                value_reduced,
                Rseed(rseed_randomness),
            ).expect("should be able to create note");
            let output_note_commitment = output_note.commit();

            let public = SettlementProofPublic { output_notes_commitments: vec![output_note_commitment], nullifiers: vec![input_note_nullifier]};
            let private = SettlementProofPrivate { output_notes: vec![output_note], input_notes: vec![input_note], setoff_amount: Amount::from(setoff_amount)};

            (public, private)
        }
    }

    proptest! {
        #[test]
        fn settlement_proof_happy_path((public, private) in arb_valid_settlement_statement()) {
            assert!(check_satisfaction(&public, &private).is_ok());
            assert!(check_circuit_satisfaction(public, private).is_ok());
        }
    }

    prop_compose! {
        // This strategy generates an settlement statement, but then replaces the note commitment
        // with one generated using an invalid note blinding factor.
        fn arb_invalid_settlement_note_commitment_integrity()(seed_phrase_randomness in any::<[u8; 32]>(), rseed_randomness in any::<[u8; 32]>(), amount in 2u64.., asset_id64 in any::<u64>(), address_index in any::<u32>(), incorrect_note_blinding in fq_strategy()) -> (SettlementProofPublic, SettlementProofPrivate) {
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

            let incorrect_note_commitment = note::commitment(
                incorrect_note_blinding,
                value_to_send,
                note.diversified_generator(),
                note.transmission_key_s(),
                note.clue_key(),
            );

            let bad_public = SettlementProofPublic { output_notes_commitments: vec![incorrect_note_commitment], nullifiers: vec![]};
            let private = SettlementProofPrivate { output_notes: vec![note], input_notes: vec![], setoff_amount: Amount::zero()};

            (bad_public, private)
        }
    }

    proptest! {
        #[test]
        /// Check that the `SettlementCircuit` is not satisfied when the note commitment is invalid.
        fn settlement_proof_verification_fails_note_commitment_integrity((public, private) in arb_invalid_settlement_note_commitment_integrity()) {
            assert!(check_satisfaction(&public, &private).is_err());
            assert!(check_circuit_satisfaction(public, private).is_err());
        }
    }
}
