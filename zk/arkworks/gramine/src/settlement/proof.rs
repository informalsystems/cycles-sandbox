use std::char::MAX;
use std::cmp::Ordering;

use anyhow::Result;
use ark_crypto_primitives::crh::poseidon::constraints::CRHParametersVar;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ff::{ToConstraintField, Zero};
use std::str::FromStr;
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
use decaf377::r1cs::FqVar;
use decaf377::{Bls12_377, Fq};
use decaf377_fmd as fmd;
use decaf377_ka as ka;
use once_cell::sync::Lazy;
use penumbra_asset::Value;
use penumbra_keys::{keys::Diversifier, Address};
use penumbra_num::{Amount, AmountVar};
use penumbra_proof_params::{DummyWitness, VerifyingKeyExt, GROTH16_PROOF_LENGTH_BYTES};
use penumbra_proto::{penumbra::core::component::shielded_pool::v1 as pb, DomainType};
use penumbra_shielded_pool::{note, Rseed};
use penumbra_tct::r1cs::StateCommitmentVar;
use poseidon377::{RATE_1_PARAMS, RATE_2_PARAMS};
use poseidon_parameters::v1::Matrix;

use crate::note::r1cs::enforce_equal_addresses;
use crate::note::{r1cs::NoteVar, Note};
use crate::nullifier::{Nullifier, NullifierVar};

pub static NULLIFIER_DOMAIN_SEP: Lazy<Fq> = Lazy::new(|| {
    Fq::from_le_bytes_mod_order(blake2b_simd::blake2b(b"penumbra.nullifier").as_bytes())
});

pub static COMMITMENTS_DOMAIN_SEP: Lazy<Fq> = Lazy::new(|| {
    Fq::from_le_bytes_mod_order(blake2b_simd::blake2b(b"penumbra.commitment").as_bytes())
});

pub static SETTLEMENT_DOMAIN_SEP: Lazy<Fq> = Lazy::new(|| {
    Fq::from_le_bytes_mod_order(blake2b_simd::blake2b(b"penumbra.settlement").as_bytes())
});

pub const MAX_PROOF_INPUT_ARRAY_SIZE: usize = 7;

/// The public input for an [`SettlementProof`].
#[derive(Clone, Debug)]
pub struct SettlementProofPublic {
    /// Hash of the input elements in `SettlementProofUncompressedPublic`
    pub pub_inputs_hash: Fq,
    /// Number of real (unpadded) elements in input arrays of `SettlementProofUncompressedPublic`
    pub len_inputs: u32,
}

/// *** Public inputs included along with the private inputs, but represented publicly with their hash ***
#[derive(Clone, Debug)]
pub struct SettlementProofUncompressedPublic {
    /// A hiding commitment to output notes.
    pub output_notes_commitments: [note::StateCommitment; MAX_PROOF_INPUT_ARRAY_SIZE],
    /// Nullifiers for input notes.
    pub nullifiers: [Nullifier; MAX_PROOF_INPUT_ARRAY_SIZE],
    // These are the public inputs to the circuit merkle tree verification circuit
    pub root: Root,
}

/// *** Truly private inputs ***
/// The private input for an [`SettlementProof`].
#[derive(Clone, Debug)]
pub struct SettlementProofPrivate {
    /// Inputs represented publicly by their hash
    pub uncompressed_public: SettlementProofUncompressedPublic,
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


trait FixedSizePadding {
    /// Produces a default/empty element for padding
    fn padding_default() -> Self;
    
    /// Creates an instance from a reference, used during padding
    fn clone_from_ref(other: &Self) -> Self;
}

impl FixedSizePadding for FqVar {
    fn padding_default() -> FqVar {
        FqVar::zero()
    }

    fn clone_from_ref(other: &Self) -> Self {
        other.clone()
    }
}

impl FixedSizePadding for note::StateCommitment {
    fn padding_default() -> note::StateCommitment {
        note::StateCommitment(Fq::zero())
    }
    
    fn clone_from_ref(other: &Self) -> Self {
        other.clone()
    }
}

impl FixedSizePadding for Nullifier {
    fn padding_default() -> Nullifier {
        Nullifier(Fq::zero())
    }

    fn clone_from_ref(other: &Self) -> Self {
        other.clone()
    }
}

impl FixedSizePadding for StateCommitmentVar {
    fn padding_default() -> Self {
        StateCommitmentVar { inner: FqVar::zero() }
    }

    fn clone_from_ref(other: &Self) -> Self {
        StateCommitmentVar { inner: other.inner.clone() }
    }
}

impl FixedSizePadding for NullifierVar {
    fn padding_default() -> Self {
        NullifierVar { inner: FqVar::zero() }
    }

    fn clone_from_ref(other: &Self) -> Self {
        NullifierVar { inner: other.inner.clone() }
    }
}


/// Pads an input slice to an array of len `MAX_PROOF_INPUT_ARRAY_SIZE`. 
/// Truncates vectors longer than `MAX_PROOF_INPUT_ARRAY_SIZE`
fn pad_to_fixed_size<F: FixedSizePadding>(elements: &[F]) -> [F; MAX_PROOF_INPUT_ARRAY_SIZE] {
    std::array::from_fn(|i| {
        elements
            .get(i)
            .map(F::clone_from_ref)
            .unwrap_or_else(F::padding_default)
    })
}

fn calculate_pub_hash(
    output_notes_commitments: &[note::StateCommitment; MAX_PROOF_INPUT_ARRAY_SIZE],
    nullifiers: &[Nullifier; MAX_PROOF_INPUT_ARRAY_SIZE],
    root: &Root,
) -> Fq {
    // Hash all commitments together
    let commitments_hash = {
        let padded_commitments = pad_to_fixed_size(output_notes_commitments);
        
        poseidon377::hash_7(
            &COMMITMENTS_DOMAIN_SEP,
            std::array::from_fn(|i| padded_commitments[i].0).into()
        )
    };
    
    // Hash all nullifiers together
    let nullifiers_hash = {
        let padded_nullifiers = pad_to_fixed_size(nullifiers);
    
        poseidon377::hash_7(
            &NULLIFIER_DOMAIN_SEP,
            std::array::from_fn(|i| padded_nullifiers[i].0).into()
        )
    };

    poseidon377::hash_3(
        &SETTLEMENT_DOMAIN_SEP,
        (commitments_hash, nullifiers_hash, root.clone()),
    )
}

fn calculate_pub_hash_var(
    cs: ConstraintSystemRef<Fq>,
    output_note_commitment_vars: &[StateCommitmentVar; MAX_PROOF_INPUT_ARRAY_SIZE],
    nullifier_vars: &[NullifierVar; MAX_PROOF_INPUT_ARRAY_SIZE],
    root_var: &RootVar,
) -> ark_relations::r1cs::Result<FqVar> {
    // Get domain separator as constant
    let commitments_var_domain_sep = FqVar::new_input(cs.clone(), || Ok(COMMITMENTS_DOMAIN_SEP.clone()))?;
    let nullifiers_var_domain_sep = FqVar::new_input(cs.clone(), || Ok(NULLIFIER_DOMAIN_SEP.clone()))?;
    let settlement_var_domain_sep = FqVar::new_input(cs.clone(), || Ok(SETTLEMENT_DOMAIN_SEP.clone()))?;

    let commitments_hash = {
        let commitments_fq: [FqVar; MAX_PROOF_INPUT_ARRAY_SIZE] = std::array::from_fn(|i| {
            output_note_commitment_vars[i].inner.clone()
        });

        // Compute hashes
        poseidon377::r1cs::hash_7(
            cs.clone(),
            &commitments_var_domain_sep,
            commitments_fq.into()
        )?
    };

    let nullifiers_hash = {
        let commitments_fq: [FqVar; MAX_PROOF_INPUT_ARRAY_SIZE] = std::array::from_fn(|i| {
            nullifier_vars[i].inner.clone()
        });

        // Compute hashes
        poseidon377::r1cs::hash_7(
            cs.clone(),
            &nullifiers_var_domain_sep,
            commitments_fq.into()
        )?
    };

    Ok(poseidon377::r1cs::hash_3(
        cs.clone(),
        &settlement_var_domain_sep,
        (commitments_hash, nullifiers_hash, root_var.clone())
    )?) 
}

#[cfg(test)]
fn check_satisfaction(
    public: &SettlementProofPublic,
    private: &SettlementProofPrivate,
) -> Result<()> {
    if public.pub_inputs_hash != calculate_pub_hash(&private.uncompressed_public.output_notes_commitments, &private.uncompressed_public.nullifiers, &private.uncompressed_public.root) {
        anyhow::bail!("Public inputs hash mismatch");
    }

    // TODO: impl note well-formedness checks
    // Loop over only the `public.len_inputs` real inputs
    for (note_commitment, note) in private
        .uncompressed_public
        .output_notes_commitments
        .iter()
        .take(public.len_inputs as usize)
        .zip(private.output_notes.iter().take(public.len_inputs as usize))
    {
        if note.diversified_generator() == decaf377::Element::default() {
            anyhow::bail!("diversified generator is identity");
        }

        if note_commitment != &note.commit() {
            anyhow::bail!("note commitment did not match public input");
        }
    }

    // Loop over only the `public.len_inputs` real inputs
    for (nullifier, note) in private
        .uncompressed_public
        .nullifiers
        .iter()
        .take(public.len_inputs as usize)
        .zip(private.input_notes.iter().take(public.len_inputs as usize))
    {
        if nullifier != &Nullifier::derive(note) {
            anyhow::bail!("nullifier did not match public input");
        }
    }

    let constants = SettlementProofConst::default();

    // `input_notes` vector is not padded`
    for (note, auth_path) in private
        .input_notes
        .iter()
        .zip(private.input_notes_proofs.iter())
    {
        let note_path_valid = auth_path.verify(
            &constants.leaf_crh_params,
            &constants.two_to_one_crh_params,
            &private.uncompressed_public.root,
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
        expected_output_notes == private.uncompressed_public.output_notes_commitments,
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
        // Witnesses
        let output_note_vars = self
            .private
            .output_notes
            .iter()
            .map(|note| NoteVar::new_witness(cs.clone(), || Ok(note.clone())))
            .collect::<Result<Vec<_>, _>>()?;
        let input_note_vars = self
            .private
            .input_notes
            .iter()
            .map(|note| NoteVar::new_witness(cs.clone(), || Ok(note.clone())))
            .collect::<Result<Vec<_>, _>>()?;
        let input_note_proof_vars = self
            .private
            .input_notes_proofs
            .iter()
            .map(|auth_path| {
                Poseidon377MerklePathVar::new_witness(ark_relations::ns!(cs, "path_var"), || {
                    Ok(auth_path)
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let setoff_var = AmountVar::new_witness(cs.clone(), || Ok(self.private.setoff_amount))?;

        let mut expected_output_note_commitment_vars = vec![];
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
            expected_output_note_commitment_vars.push(note_var.commit()?);
        }

        // Public inputs
        // TODO: bug! These StateCommitmentVars are being produced differently than the hash does
        let output_note_commitment_vars = self
            .private
            .uncompressed_public
            .output_notes_commitments
            .iter()
            .map(|commitment| StateCommitmentVar::new_input(cs.clone(), || Ok(*commitment)))
            .collect::<Result<Vec<_>, _>>()?;
        let nullifier_vars = self
            .private
            .uncompressed_public
            .nullifiers
            .iter()
            .map(|nullifier| NullifierVar::new_input(cs.clone(), || Ok(*nullifier)))
            .collect::<Result<Vec<_>, _>>()?;
        let root_var = RootVar::new_input(cs.clone(), || Ok(self.private.uncompressed_public.root))?;
        let pub_inputs_hash_var = FqVar::new_input(cs.clone(), || Ok(self.public.pub_inputs_hash))?;

        // Constants
        let constants = SettlementProofConst::default();
        let leaf_crh_params_var =
            CRHParametersVar::new_constant(cs.clone(), &constants.leaf_crh_params)?;
        let two_to_one_crh_params_var =
            CRHParametersVar::new_constant(cs.clone(), &constants.two_to_one_crh_params)?;
        let zero_var = AmountVar::new_constant(cs.clone(), Amount::zero())?;

        // TODO: impl note well-formedness checks

        // Check public input hash matches actual inputs

        let padded_commitments= &pad_to_fixed_size(&output_note_commitment_vars);
        let padded_nullifiers= &pad_to_fixed_size(&nullifier_vars);
        let computed_hash_var = calculate_pub_hash_var(
            cs,
            &padded_commitments,
            &padded_nullifiers,
            &root_var
        )?;
        computed_hash_var.enforce_equal(&pub_inputs_hash_var)?;

        // Note commitment integrity check
        // Loop only over non-padding commitments
        for (output_note_commitment_var, output_note_var) in output_note_commitment_vars
            .iter()
            .take(self.public.len_inputs as usize)
            .zip(output_note_vars.iter().take(self.public.len_inputs as usize))
        {
            let note_commitment = output_note_var.commit()?;
            note_commitment.enforce_equal(output_note_commitment_var)?;
        }

        // Nullifier integrity check
        // Loop only over non-padding nullifiers
        for (claimed_nullifier_var, note_var) in nullifier_vars
            .iter()
            .take(self.public.len_inputs as usize)
            .zip(input_note_vars.iter().take(self.public.len_inputs as usize))
        {
            let nullifier_var = NullifierVar::derive(note_var)?;
            nullifier_var.enforce_equal(claimed_nullifier_var)?;
        }

        for (input_note_var, input_note_proof_var) in
            input_note_vars
            .iter()
            .zip(input_note_proof_vars.iter())
        {
            let is_member = input_note_proof_var.verify_membership(
                &leaf_crh_params_var,
                &two_to_one_crh_params_var,
                &root_var,
                &[input_note_var.commit()?.inner],
            )?;
            is_member.enforce_equal(&Boolean::TRUE)?;
        }

        for input_note_var in input_note_vars.windows(2) {
            let curr_creditor = &input_note_var[0].creditor;
            let next_debtor = &input_note_var[1].debtor;
            enforce_equal_addresses(curr_creditor, next_debtor)?;
        }
        let first_debtor = input_note_vars
            .first()
            .map(|n| &n.debtor)
            .ok_or(SynthesisError::Unsatisfiable)?;
        let last_creditor = input_note_vars
            .last()
            .map(|n| &n.creditor)
            .ok_or(SynthesisError::Unsatisfiable)?;
        enforce_equal_addresses(first_debtor, last_creditor)?;

        // fixme: Do we need to check there are >1 input notes?

        // setoff_amount > 0
        setoff_var
            .amount
            .enforce_cmp(&zero_var.amount, Ordering::Greater, false)?;

        // min_amount >= setoff_amount
        for input_note_var in &input_note_vars {
            input_note_var.value.amount.amount.enforce_cmp(
                &setoff_var.amount,
                Ordering::Greater,
                true,
            )?
        }

        // check output notes correspond to reduced input notes
        for (expected, claimed) in expected_output_note_commitment_vars
            .iter()
            .zip(output_note_commitment_vars.iter())
        {
            expected.enforce_equal(claimed)?;
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

        let output_notes_commitments = pad_to_fixed_size(&[note.commit()]);
        let nullifiers = pad_to_fixed_size(&[Nullifier::derive(&note)]);

        let pub_inputs_hash = calculate_pub_hash(&output_notes_commitments, &nullifiers, &tree.root());

        let public = SettlementProofPublic {
            pub_inputs_hash,
            len_inputs: 1
        };

        let private = SettlementProofPrivate {
            uncompressed_public: SettlementProofUncompressedPublic {
                output_notes_commitments: [note.commit(); MAX_PROOF_INPUT_ARRAY_SIZE],
                nullifiers: [Nullifier::derive(&note); MAX_PROOF_INPUT_ARRAY_SIZE],
                root: tree.root(),    
            },
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
        public_inputs_hash: Fq,
        public: SettlementProofUncompressedPublic,
    ) -> anyhow::Result<()> {
        // Check that the proof's public input hash matches the hash of inputs
        if public_inputs_hash != calculate_pub_hash(&public.output_notes_commitments, &public.nullifiers, &public.root) {
            anyhow::bail!("Public inputs hash mismatch");
        }

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

            let output_notes_commitments = pad_to_fixed_size(&[output_note_commitment_1, output_note_commitment_2]);
            let nullifiers = pad_to_fixed_size(&[input_note_nullifier_1, input_note_nullifier_2]);

            let pub_inputs_hash = calculate_pub_hash(&output_notes_commitments, &nullifiers, &tree.root());

            let public = SettlementProofPublic {
                pub_inputs_hash,
                len_inputs: 2
            };
            let private = SettlementProofPrivate {
                uncompressed_public: SettlementProofUncompressedPublic {
                    output_notes_commitments,
                    nullifiers,
                    root: tree.root(),    
                },
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
            let incorrect_output_note_commitment_2 = commitment(
                incorrect_note_blinding,
                value_to_send,
                output_note_2.diversified_generator(),
                output_note_2.transmission_key_s(),
                output_note_2.clue_key(),
                output_note_2.creditor().transmission_key_s().clone()
            );

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

            let output_notes_commitments = pad_to_fixed_size(&[output_note_commitment_1, incorrect_output_note_commitment_2]);
            let nullifiers = pad_to_fixed_size(&[input_note_nullifier_1, input_note_nullifier_2]);

            let pub_inputs_hash = calculate_pub_hash(&output_notes_commitments, &nullifiers, &tree.root());

            let bad_public = SettlementProofPublic {
                pub_inputs_hash,
                len_inputs: 2
            };

            let private = SettlementProofPrivate {
                uncompressed_public: SettlementProofUncompressedPublic {
                    output_notes_commitments,
                    nullifiers,
                    root: tree.root(),    
                },
                output_notes: vec![output_note_1, output_note_2],
                input_notes: vec![input_note_1, input_note_2],
                setoff_amount: Amount::from(setoff_amount),
                input_notes_proofs: vec![input_auth_path_1, input_auth_path_2]
            };

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
