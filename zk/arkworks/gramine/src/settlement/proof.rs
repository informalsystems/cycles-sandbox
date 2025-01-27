use std::cmp::Ordering;
use std::str::FromStr;

use anyhow::Result;
use ark_crypto_primitives::crh::poseidon::constraints::CRHParametersVar;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ff::ToConstraintField;
use ark_groth16::r1cs_to_qap::LibsnarkReduction;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey};
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use arkworks_merkle_tree::poseidontree::{
    LeafHashParams, Poseidon377MerklePath, Poseidon377MerklePathVar, Poseidon377MerkleTree, Root,
    RootVar, TwoToOneHashParams,
};
use base64::prelude::*;
use decaf377::{Bls12_377, Fq};
use decaf377_fmd as fmd;
use decaf377_ka as ka;
use penumbra_asset::{Value, ValueVar};
use penumbra_keys::{keys::Diversifier, Address, AddressVar};
use penumbra_num::{Amount, AmountVar};
use penumbra_proof_params::{DummyWitness, VerifyingKeyExt, GROTH16_PROOF_LENGTH_BYTES};
use penumbra_proto::{penumbra::core::component::shielded_pool::v1 as pb, DomainType};
use penumbra_shielded_pool::{note, Rseed};
use penumbra_tct::r1cs::StateCommitmentVar;
use poseidon377::{RATE_1_PARAMS, RATE_2_PARAMS};
use poseidon_parameters::v1::Matrix;

use crate::note::{r1cs::NoteVar, Note};
use crate::nullifier::{Nullifier, NullifierVar};

/// The public input for an [`SettlementProof`].
#[derive(Clone, Debug)]
pub struct SettlementProofPublic {
    /// A hiding commitment to output notes.
    pub output_notes_commitments: Vec<note::StateCommitment>,
    /// Nullifiers for input notes.
    pub nullifiers: Vec<Nullifier>,
    // These are the public inputs to the circuit merkle tree verification circuit
    pub root: Root,
}

/// The private input for an [`SettlementProof`].
#[derive(Clone, Debug)]
pub struct SettlementProofPrivate {
    /// The output notes being created.
    pub output_notes: Vec<Note>,
    /// The input notes being spent.
    pub input_notes: Vec<Note>,
    /// Membership proof for all input notes.
    pub input_notes_proofs: Vec<Poseidon377MerklePath>,
    /// Setoff amount for this cycle.
    pub setoff_amount: Amount,
}

/// The const input for an [`SettlementProof`].
#[derive(Clone, Debug)]
pub struct SettlementProofConst {
    // Poseidon CRH constants that will be embedded into the circuit
    pub leaf_crh_params: LeafHashParams,
    pub two_to_one_crh_params: TwoToOneHashParams,
}

impl Default for SettlementProofConst {
    fn default() -> Self {
        // fixme: unsafe alpha conversion?
        let leaf_crh_params = {
            let params = RATE_1_PARAMS;
            PoseidonConfig::<Fq>::new(
                params.rounds.full(),
                params.rounds.partial(),
                u32::from_le_bytes(params.alpha.to_bytes_le()).into(),
                params.mds.0 .0.into_nested_vec(),
                params.arc.0.into_nested_vec(),
                1,
                1,
            )
        };
        let two_to_one_crh_params = {
            let params = RATE_2_PARAMS;
            PoseidonConfig::<Fq>::new(
                params.rounds.full(),
                params.rounds.partial(),
                u32::from_le_bytes(params.alpha.to_bytes_le()).into(),
                params.mds.0 .0.into_nested_vec(),
                params.arc.0.into_nested_vec(),
                2,
                1,
            )
        };
        Self {
            leaf_crh_params,
            two_to_one_crh_params,
        }
    }
}

pub trait MatrixExt {
    fn into_nested_vec(self) -> Vec<Vec<Fq>>;
}

impl<const N_ROWS: usize, const N_COLS: usize, const N_ELEMENTS: usize> MatrixExt
    for Matrix<N_ROWS, N_COLS, N_ELEMENTS>
{
    fn into_nested_vec(self) -> Vec<Vec<Fq>> {
        self.elements
            .chunks(N_COLS)
            .map(|row| row.to_vec())
            .collect()
    }
}

#[cfg(test)]
fn check_satisfaction(
    public: &SettlementProofPublic,
    private: &SettlementProofPrivate,
) -> Result<()> {
    // TODO: impl note well-formedness checks

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

    let constants = SettlementProofConst::default();

    for (note, auth_path) in private
        .input_notes
        .iter()
        .zip(private.input_notes_proofs.iter())
    {
        let note_path_valid = auth_path.verify(
            &constants.leaf_crh_params,
            &constants.two_to_one_crh_params,
            &public.root,
            [note.commit().0],
        );
        anyhow::ensure!(
            note_path_valid.is_ok(),
            format!("couldn't verify note auth path for note {:?}", note)
        )
    }

    for notes in private.input_notes.windows(2) {
        anyhow::ensure!(
            notes[0].creditor() == notes[1].debtor(),
            "creditor does not match debtor in settlement flow"
        );
    }
    anyhow::ensure!(
        private.input_notes.first().unwrap().debtor()
            == private.input_notes.last().unwrap().creditor(),
        "first debtor does not match last creditor in settlement flow"
    );

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
            Note::from_parts(note.debtor(), note.creditor(), new_value, note.rseed())?
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
        // TODO: impl note well-formedness checks

        for (note_commitment, note) in self
            .public
            .output_notes_commitments
            .iter()
            .zip(self.private.output_notes.iter())
        {
            // Witnesses
            // Note: In the allocation of the address on `NoteVar`, we check the diversified base is not identity.
            let note_var = NoteVar::new_witness(cs.clone(), || Ok(note.clone()))?;

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
            let note_var = NoteVar::new_witness(cs.clone(), || Ok(note.clone()))?;

            // Public inputs
            let claimed_nullifier_var = NullifierVar::new_input(cs.clone(), || Ok(nullifier))?;

            let nullifier_var = NullifierVar::derive(&note_var)?;
            nullifier_var.enforce_equal(&claimed_nullifier_var)?;
        }

        let constants = SettlementProofConst::default();

        for (note, auth_path) in self
            .private
            .input_notes
            .iter()
            .zip(self.private.input_notes_proofs.iter())
        {
            let path_var =
                Poseidon377MerklePathVar::new_witness(ark_relations::ns!(cs, "path_var"), || {
                    Ok(auth_path)
                })?;

            let note_var = NoteVar::new_witness(cs.clone(), || Ok(note.clone()))?;
            let root_var = RootVar::new_input(cs.clone(), || Ok(self.public.root.clone()))?;

            // Then, we allocate the public parameters as constants:
            let leaf_crh_params_var =
                CRHParametersVar::new_constant(cs.clone(), &constants.leaf_crh_params)?;
            let two_to_one_crh_params_var =
                CRHParametersVar::new_constant(cs.clone(), &constants.two_to_one_crh_params)?;

            let is_member = path_var.verify_membership(
                &leaf_crh_params_var,
                &two_to_one_crh_params_var,
                &root_var,
                &[note_var.commit()?.inner],
            )?;
            is_member.enforce_equal(&Boolean::TRUE)?;
        }

        fn enforce_equal_addresses(
            addr1: AddressVar,
            addr2: AddressVar,
        ) -> Result<(), SynthesisError> {
            let AddressVar {
                diversified_generator,
                transmission_key,
                clue_key,
            } = addr1;
            addr2
                .diversified_generator
                .enforce_equal(&diversified_generator)?;
            addr2.transmission_key.enforce_equal(&transmission_key)?;
            addr2.clue_key.enforce_equal(&clue_key)?;
            Ok(())
        }

        let debtor_var = |n: &Note| AddressVar::new_witness(cs.clone(), || Ok(n.debtor()));
        let creditor_var = |n: &Note| AddressVar::new_witness(cs.clone(), || Ok(n.creditor()));
        for notes in self.private.input_notes.windows(2) {
            let curr_creditor = creditor_var(&notes[0])?;
            let next_debtor = debtor_var(&notes[1])?;
            enforce_equal_addresses(curr_creditor, next_debtor)?;
        }
        let first_debtor = self
            .private
            .input_notes
            .first()
            .map(debtor_var)
            .ok_or_else(|| SynthesisError::Unsatisfiable)??;
        let last_creditor = self
            .private
            .input_notes
            .last()
            .map(creditor_var)
            .ok_or_else(|| SynthesisError::Unsatisfiable)??;
        enforce_equal_addresses(first_debtor, last_creditor)?;

        // fixme: Do we need to check there are >1 input notes?

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
                let note =
                    Note::from_parts(note.debtor(), note.creditor(), new_value, note.rseed())
                        .map_err(|_| SynthesisError::Unsatisfiable)?;
                NoteVar::new_witness(cs.clone(), || Ok(note.clone()))?
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
            address.clone(),
            address,
            Value::from_str("1upenumbra").expect("valid value"),
            Rseed([1u8; 32]),
        )
        .expect("can make a note");

        // Merkle tree circuit setup steps
        let constants = SettlementProofConst::default();

        // Enter duplicate commit to satisfy the need for >1 leaves in the `MerkleTree::new` function
        let leaves: Vec<[Fq; 1]> = vec![[note.commit().0], [note.commit().0]];

        // Build tree with our one dummy note in order to get the merkle root value
        let tree = Poseidon377MerkleTree::new(
            &constants.leaf_crh_params,
            &constants.two_to_one_crh_params,
            leaves.clone(),
        )
        .unwrap();

        // Get auth path from 0th leaf to root
        let auth_path = tree.generate_proof(0).unwrap();

        let public = SettlementProofPublic {
            output_notes_commitments: vec![note.commit()],
            nullifiers: vec![Nullifier::derive(&note)],
            root: tree.root(),
        };
        let private = SettlementProofPrivate {
            output_notes: vec![note.clone()],
            input_notes: vec![note],
            setoff_amount: Amount::zero(),
            input_notes_proofs: vec![auth_path],
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

    fn address_from_seed(seed_phrase_randomness: &[u8], index: u32) -> Address {
        let seed_phrase = SeedPhrase::from_randomness(&seed_phrase_randomness);
        let sk_recipient = SpendKey::from_seed_phrase_bip44(seed_phrase, &Bip44Path::new(0));
        let fvk_recipient = sk_recipient.full_viewing_key();
        let ivk_recipient = fvk_recipient.incoming();
        let (dest, _dtk_d) = ivk_recipient.payment_address(index.into());
        dest
    }

    prop_compose! {
        fn arb_valid_settlement_statement()(
            seed_phrase_randomness_1 in any::<[u8; 32]>(),
            seed_phrase_randomness_2 in any::<[u8; 32]>(),
            rseed_randomness in any::<[u8; 32]>(),
            amount in 2u64.., asset_id64 in any::<u64>(),
            address_index_1 in any::<u32>(),
            address_index_2 in any::<u32>()
        ) -> (SettlementProofPublic, SettlementProofPrivate) {
            let dest_debtor = address_from_seed(&seed_phrase_randomness_1, address_index_1);
            let dest_creditor = address_from_seed(&seed_phrase_randomness_2, address_index_2);

            let value_to_send = Value {
                amount: Amount::from(amount),
                asset_id: asset::Id(Fq::from(asset_id64)),
            };
            let input_note_1 = Note::from_parts(
                dest_debtor.clone(),
                dest_creditor.clone(),
                value_to_send,
                Rseed(rseed_randomness),
            ).expect("should be able to create note");
            let input_note_nullifier_1 = Nullifier::derive(&input_note_1);

            let input_note_2 = Note::from_parts(
                dest_creditor.clone(),
                dest_debtor.clone(),
                value_to_send,
                Rseed(rseed_randomness),
            ).expect("should be able to create note");
            let input_note_nullifier_2 = Nullifier::derive(&input_note_2);

            let setoff_amount = amount;
            let value_reduced = Value {
                amount: Amount::from(amount - setoff_amount),
                asset_id: asset::Id(Fq::from(asset_id64)),
            };
            let output_note_1 = Note::from_parts(
                dest_debtor.clone(),
                dest_creditor.clone(),
                value_reduced,
                Rseed(rseed_randomness),
            ).expect("should be able to create note");
            let output_note_commitment_1 = output_note_1.commit();
            let output_note_2 = Note::from_parts(
                dest_creditor,
                dest_debtor,
                value_reduced,
                Rseed(rseed_randomness),
            ).expect("should be able to create note");
            let output_note_commitment_2 = output_note_2.commit();

            let constants = SettlementProofConst::default();
            let leaves: Vec<[Fq; 1]> = vec![[input_note_1.commit().0], [input_note_2.commit().0]];
            // Build tree with our one dummy note in order to get the merkle root value
            let tree = Poseidon377MerkleTree::new(
                &constants.leaf_crh_params,
                &constants.two_to_one_crh_params,
                leaves.clone(),
            )
            .unwrap();

            // Get auth path from 0th leaf to root (input note)
            let input_auth_path_1 = tree.generate_proof(0).unwrap();
            let input_auth_path_2 = tree.generate_proof(1).unwrap();

            let public = SettlementProofPublic {
                output_notes_commitments: vec![output_note_commitment_1, output_note_commitment_2],
                nullifiers: vec![input_note_nullifier_1, input_note_nullifier_2],
                root: tree.root(),
            };
            let private = SettlementProofPrivate {
                output_notes: vec![output_note_1, output_note_2],
                input_notes: vec![input_note_1, input_note_2],
                setoff_amount: Amount::from(setoff_amount),
                input_notes_proofs: vec![input_auth_path_1, input_auth_path_2]
            };

            (public, private)
        }
    }

    proptest! {
        #[test]
        fn settlement_proof_happy_path((public, private) in arb_valid_settlement_statement()) {
            if let Err(e) = check_satisfaction(&public, &private) {
                println!("check_satisfaction failed: {:?}", e);
                assert!(false, "check_satisfaction failed");
            }
            if let Err(e) = check_circuit_satisfaction(public, private) {
                println!("check_circuit_satisfaction failed: {:?}", e);
                assert!(false, "check_circuit_satisfaction failed");
            }
        }
    }

    prop_compose! {
        // This strategy generates an settlement statement, but then replaces the note commitment
        // with one generated using an invalid note blinding factor.
        fn arb_invalid_settlement_note_commitment_integrity()(
            seed_phrase_randomness_1 in any::<[u8; 32]>(),
            seed_phrase_randomness_2 in any::<[u8; 32]>(),
            rseed_randomness in any::<[u8; 32]>(),
            amount in 2u64.., asset_id64 in any::<u64>(),
            address_index_1 in any::<u32>(),
            address_index_2 in any::<u32>(),
            incorrect_note_blinding in fq_strategy()
        ) -> (SettlementProofPublic, SettlementProofPrivate) {
            let dest_debtor = address_from_seed(&seed_phrase_randomness_1, address_index_1);
            let dest_creditor = address_from_seed(&seed_phrase_randomness_2, address_index_2);

            let value_to_send = Value {
                amount: Amount::from(amount),
                asset_id: asset::Id(Fq::from(asset_id64)),
            };
            let note = Note::from_parts(
                dest_debtor,
                dest_creditor,
                value_to_send,
                Rseed(rseed_randomness),
            ).expect("should be able to create note");
            let nullifier = Nullifier::derive(&note);

            let incorrect_note_commitment = commitment(
                incorrect_note_blinding,
                value_to_send,
                note.diversified_generator(),
                note.transmission_key_s(),
                note.clue_key(),
                note.creditor().transmission_key_s().clone()
            );

            let constants = SettlementProofConst::default();
            let leaves: Vec<[Fq; 1]> = vec![[note.commit().0]];

            // Build tree with our one dummy note in order to get the merkle root value
            let tree = Poseidon377MerkleTree::new(
                &constants.leaf_crh_params,
                &constants.two_to_one_crh_params,
                leaves.clone(),
            )
            .unwrap();

            // Get auth path from 0th leaf to root (input note)
            let input_auth_path = tree.generate_proof(0).unwrap();

            let bad_public = SettlementProofPublic { output_notes_commitments: vec![incorrect_note_commitment], nullifiers: vec![nullifier], root: tree.root()};
            let private = SettlementProofPrivate { output_notes: vec![note], input_notes: vec![], setoff_amount: Amount::zero(), input_notes_proofs: vec![input_auth_path]};

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
