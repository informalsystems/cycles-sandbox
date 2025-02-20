use std::cmp::Ordering;

use anyhow::Result;
use ark_crypto_primitives::crh::poseidon::constraints::CRHParametersVar;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ff::{ToConstraintField, Zero};
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
use decaf377::r1cs::{ElementVar, FqVar};
use decaf377::{Bls12_377, Encoding, Fq};
use decaf377_ka::Public;
use decaf377_rdsa::{SpendAuth, VerificationKey};
use once_cell::sync::Lazy;
use penumbra_asset::Value;
use penumbra_keys::keys::{
    AuthorizationKeyVar, Bip44Path, IncomingViewingKeyVar, NullifierKey, NullifierKeyVar,
    SeedPhrase, SpendKey,
};
use penumbra_keys::{test_keys, Address};
use penumbra_num::{Amount, AmountVar};
use penumbra_proof_params::{DummyWitness, VerifyingKeyExt, GROTH16_PROOF_LENGTH_BYTES};
use penumbra_proto::{penumbra::core::component::shielded_pool::v1 as pb, DomainType};
use penumbra_shielded_pool::{note::StateCommitment, Rseed};
use penumbra_tct::r1cs::StateCommitmentVar;
use poseidon377::{RATE_1_PARAMS, RATE_2_PARAMS};
use poseidon_parameters::v1::Matrix;

use crate::encryption::r1cs::{CiphertextVar, PlaintextVar, PublicKeyVar, SharedSecretVar};
use crate::encryption::{ecies_encrypt, r1cs, Ciphertext};
use crate::note::{r1cs::enforce_equal_addresses, r1cs::NoteVar, Note};
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
}

/// *** Public inputs included along with the private inputs, but represented publicly with their hash ***
#[derive(Clone, Debug)]
pub struct SettlementProofUncompressedPublic<const N: usize> {
    /// A hiding commitment to output notes.
    pub output_notes_commitments: [StateCommitment; N],
    /// Nullifiers for input notes.
    pub nullifiers: [Nullifier; N],
    /// These are the public inputs to the circuit merkle tree verification circuit
    pub root: Root,
    /// Note ciphertexts encrypted using the note's esk.
    pub note_ciphertexts: [Ciphertext; N],
    /// Shared secret ciphertexts encrypted using the note's shared secret.
    pub ss_ciphertexts: [Ciphertext; N],
    /// Note ephemeral public keys.
    pub note_epks: [Public; N],
}

/// *** Truly private inputs ***
/// The private input for an [`SettlementProof`].
#[derive(Clone, Debug)]
pub struct SettlementProofPrivate<const N: usize> {
    /// Inputs represented publicly by their hash
    pub uncompressed_public: SettlementProofUncompressedPublic<N>,
    /// The output notes being created; missing entries are None
    pub output_notes: [Note; N],
    /// The input notes being spent; missing entries are None
    pub input_notes: [Note; N],
    /// Membership proofs for all input notes; missing entries are None
    pub input_notes_proofs: [Poseidon377MerklePath; N],
    /// Setoff amount for this cycle.
    pub setoff_amount: Amount,
    /// The solver's spend verification key (needed to compute `solver_ivk` in circuit)
    pub solver_ak: VerificationKey<SpendAuth>,
    /// The solver's nullifier deriving key (needed to compute `solver_ivk` in circuit)
    pub solver_nk: NullifierKey,
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

impl FixedSizePadding for StateCommitment {
    fn padding_default() -> StateCommitment {
        StateCommitment(Fq::zero())
    }

    fn clone_from_ref(other: &Self) -> Self {
        *other
    }
}

impl FixedSizePadding for Nullifier {
    fn padding_default() -> Nullifier {
        Nullifier(Fq::zero())
    }

    fn clone_from_ref(other: &Self) -> Self {
        *other
    }
}

impl FixedSizePadding for StateCommitmentVar {
    fn padding_default() -> Self {
        StateCommitmentVar {
            inner: FqVar::zero(),
        }
    }

    fn clone_from_ref(other: &Self) -> Self {
        StateCommitmentVar {
            inner: other.inner.clone(),
        }
    }
}

impl FixedSizePadding for NullifierVar {
    fn padding_default() -> Self {
        NullifierVar {
            inner: FqVar::zero(),
        }
    }

    fn clone_from_ref(other: &Self) -> Self {
        NullifierVar {
            inner: other.inner.clone(),
        }
    }
}

impl FixedSizePadding for Note {
    fn padding_default() -> Self {
        let mut rng = rand::thread_rng();
        fn rand_address(seed: &[u8]) -> Address {
            let randomness = SeedPhrase::from_randomness(seed);
            let sk = SpendKey::from_seed_phrase_bip44(randomness, &Bip44Path::new(0));
            let fvk = sk.full_viewing_key();
            let ivk = fvk.incoming();
            let (addr, _) = ivk.payment_address(0u32.into());
            addr
        }

        Note::from_parts(
            rand_address(&[1; 32]),
            rand_address(&[2; 32]),
            Value {
                amount: Amount::zero(),
                asset_id: penumbra_asset::asset::Id(Fq::rand(&mut rng)),
            },
            Rseed::generate(&mut rng),
        )
        .unwrap()
    }

    fn clone_from_ref(other: &Self) -> Self {
        other.clone()
    }
}

impl FixedSizePadding for Poseidon377MerklePath {
    fn padding_default() -> Self {
        Poseidon377MerklePath::default()
    }

    fn clone_from_ref(other: &Self) -> Self {
        other.clone()
    }
}

impl FixedSizePadding for Ciphertext {
    fn padding_default() -> Self {
        vec![]
    }

    fn clone_from_ref(other: &Self) -> Self {
        other.clone()
    }
}

impl FixedSizePadding for Public {
    fn padding_default() -> Self {
        Public([0u8; 32])
    }

    fn clone_from_ref(other: &Self) -> Self {
        *other
    }
}

/// Pads an input slice to an array of len `MAX_PROOF_INPUT_ARRAY_SIZE`.
/// Truncates vectors longer than `MAX_PROOF_INPUT_ARRAY_SIZE`
fn pad_to_fixed_size<F: FixedSizePadding>(
    elements: &[F],
) -> anyhow::Result<[F; MAX_PROOF_INPUT_ARRAY_SIZE]> {
    anyhow::ensure!(
        elements.len() <= MAX_PROOF_INPUT_ARRAY_SIZE,
        "input array size is larger than max"
    );

    Ok(std::array::from_fn(|i| {
        elements
            .get(i)
            .map(F::clone_from_ref)
            .unwrap_or_else(F::padding_default)
    }))
}

fn calculate_pub_hash(
    output_notes_commitments: &[StateCommitment; MAX_PROOF_INPUT_ARRAY_SIZE],
    nullifiers: &[Nullifier; MAX_PROOF_INPUT_ARRAY_SIZE],
    root: &Root,
) -> Fq {
    // Hash all commitments together
    let commitments_hash = poseidon377::hash_7(
        &COMMITMENTS_DOMAIN_SEP,
        std::array::from_fn(|i| output_notes_commitments[i].0).into(),
    );

    // Hash all nullifiers together
    let nullifiers_hash = poseidon377::hash_7(
        &NULLIFIER_DOMAIN_SEP,
        std::array::from_fn(|i| nullifiers[i].0).into(),
    );

    poseidon377::hash_3(
        &SETTLEMENT_DOMAIN_SEP,
        (commitments_hash, nullifiers_hash, *root),
    )
}

fn calculate_pub_hash_var(
    cs: ConstraintSystemRef<Fq>,
    output_note_commitment_vars: &[StateCommitmentVar; MAX_PROOF_INPUT_ARRAY_SIZE],
    nullifier_vars: &[NullifierVar; MAX_PROOF_INPUT_ARRAY_SIZE],
    root_var: &RootVar,
) -> ark_relations::r1cs::Result<FqVar> {
    // Get domain separator as constant
    let commitments_var_domain_sep = FqVar::new_constant(cs.clone(), *COMMITMENTS_DOMAIN_SEP)?;
    let nullifiers_var_domain_sep = FqVar::new_constant(cs.clone(), *NULLIFIER_DOMAIN_SEP)?;
    let settlement_var_domain_sep = FqVar::new_constant(cs.clone(), *SETTLEMENT_DOMAIN_SEP)?;

    let commitments_hash = {
        let commitments_fq: [FqVar; MAX_PROOF_INPUT_ARRAY_SIZE] =
            std::array::from_fn(|i| output_note_commitment_vars[i].inner.clone());

        // Compute hashes
        poseidon377::r1cs::hash_7(
            cs.clone(),
            &commitments_var_domain_sep,
            commitments_fq.into(),
        )?
    };

    let nullifiers_hash = {
        let commitments_fq: [FqVar; MAX_PROOF_INPUT_ARRAY_SIZE] =
            std::array::from_fn(|i| nullifier_vars[i].inner.clone());

        // Compute hashes
        poseidon377::r1cs::hash_7(
            cs.clone(),
            &nullifiers_var_domain_sep,
            commitments_fq.into(),
        )?
    };

    poseidon377::r1cs::hash_3(
        cs.clone(),
        &settlement_var_domain_sep,
        (commitments_hash, nullifiers_hash, root_var.clone()),
    )
}

#[cfg(test)]
fn check_satisfaction(
    public: &SettlementProofPublic,
    private: &SettlementProofPrivate<MAX_PROOF_INPUT_ARRAY_SIZE>,
) -> Result<()> {
    use crate::encryption::ecies_decrypt;
    use penumbra_keys::FullViewingKey;

    if public.pub_inputs_hash
        != calculate_pub_hash(
            &private.uncompressed_public.output_notes_commitments,
            &private.uncompressed_public.nullifiers,
            &private.uncompressed_public.root,
        )
    {
        anyhow::bail!("Public inputs hash mismatch");
    }

    let unpadded_len = private
        .input_notes
        .iter()
        .position(|n| n.amount() == Amount::zero())
        .unwrap_or(MAX_PROOF_INPUT_ARRAY_SIZE);

    // TODO: impl note well-formedness checks

    for (note_commitment, note) in private
        .uncompressed_public
        .output_notes_commitments
        .iter()
        .take(unpadded_len)
        .zip(private.output_notes.iter())
    {
        if note.diversified_generator() == decaf377::Element::default() {
            anyhow::bail!("diversified generator is identity");
        }

        if note_commitment != &note.commit() {
            anyhow::bail!("note commitment did not match public input");
        }
    }

    for (nullifier, note) in private
        .uncompressed_public
        .nullifiers
        .iter()
        .take(unpadded_len)
        .zip(private.input_notes.iter())
    {
        if nullifier != &Nullifier::derive(note) {
            anyhow::bail!("nullifier did not match public input");
        }
    }

    let constants = SettlementProofConst::default();

    // verify merkle proofs
    for (note, auth_path) in private
        .input_notes
        .iter()
        .take(unpadded_len)
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

    for notes in private.input_notes.windows(2).take(unpadded_len - 1)
    // stop before we get to a pair where the second note is padded
    {
        anyhow::ensure!(
            notes[0].creditor() == notes[1].debtor(),
            "creditor does not match debtor in settlement flow"
        );
    }
    anyhow::ensure!(
        private.input_notes.first().unwrap().debtor()
            == private.input_notes[unpadded_len - 1].creditor(),
        "first debtor does not match last creditor in settlement flow"
    );

    anyhow::ensure!(
        private.setoff_amount > Amount::zero(),
        "non-positive setoff amount"
    );

    for input_note in private.input_notes.iter().take(unpadded_len) {
        anyhow::ensure!(
            input_note.amount() >= private.setoff_amount,
            "note amount is less than setoff amount"
        );
    }

    let mut expected_output_notes = vec![];
    for note in private.input_notes.iter().take(unpadded_len) {
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
        expected_output_notes
            == private.uncompressed_public.output_notes_commitments[..expected_output_notes.len()],
        "expected output notes do not match claimed"
    );

    // prove output notes were encrypted to same shared secret as input notes (or equivalently ss_ciphertexts)
    let solver_ivk = FullViewingKey::from_components(private.solver_ak, private.solver_nk)
        .incoming()
        .clone();
    for (((ss_ciphertext, epk), output_note), note_ciphertext) in private
        .uncompressed_public
        .ss_ciphertexts
        .iter()
        .take(unpadded_len)
        .zip(private.uncompressed_public.note_epks.iter())
        .zip(private.output_notes.iter())
        .zip(private.uncompressed_public.note_ciphertexts.iter())
    {
        // Compute the shared secret `s` by performing key agreement, decompressing, and decrypting.
        let s = {
            // Perform key agreement to obtain the shared secret used to encrypt the note's shared secret.
            let ss = solver_ivk.key_agreement_with(epk)?;
            let s_tee = Encoding(ss.0)
                .vartime_decompress()
                .map_err(|e| anyhow::anyhow!(e))?;

            // Decrypt to recover the note's shared secret.
            let plaintext_fq_vec = ecies_decrypt(s_tee, ss_ciphertext.clone())?;
            let s_fq = plaintext_fq_vec
                .first()
                .ok_or_else(|| anyhow::anyhow!("Decryption yielded an empty plaintext vector"))?;
            Encoding(s_fq.to_bytes())
                .vartime_decompress()
                .map_err(|e| anyhow::anyhow!(e))?
        };

        // Encrypt the output note (after converting it to field elements)
        // and verify that the ciphertext matches the expected value.
        let note_field_elements = output_note.to_field_elements().unwrap();
        let ciphertext = ecies_encrypt(s, note_field_elements)?;
        anyhow::ensure!(ciphertext == *note_ciphertext);
    }

    Ok(())
}

#[cfg(test)]
fn check_circuit_satisfaction(
    public: SettlementProofPublic,
    private: SettlementProofPrivate<MAX_PROOF_INPUT_ARRAY_SIZE>,
) -> Result<()> {
    use ark_relations::r1cs::{self, ConstraintSystem};

    let cs = ConstraintSystem::new_ref();
    let circuit = SettlementCircuit::new(public, private)?;
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
pub struct SettlementCircuit<const N: usize = MAX_PROOF_INPUT_ARRAY_SIZE> {
    public: SettlementProofPublic,
    private: SettlementProofPrivate<N>,
}

impl<const N: usize> SettlementCircuit<N> {
    fn new(
        public: SettlementProofPublic,
        private: SettlementProofPrivate<N>,
    ) -> Result<SettlementCircuit, anyhow::Error> {
        let private = private.padded()?;
        Ok(SettlementCircuit { public, private })
    }
}

impl ConstraintSynthesizer<Fq> for SettlementCircuit<MAX_PROOF_INPUT_ARRAY_SIZE> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fq>) -> ark_relations::r1cs::Result<()> {
        let unpadded_len = self
            .private
            .input_notes
            .iter()
            .position(|n| n.amount() == Amount::zero())
            .unwrap_or(MAX_PROOF_INPUT_ARRAY_SIZE);

        // Witnesses
        let output_note_ser_vars = self
            .private
            .output_notes
            .iter()
            .map(|note| {
                note.to_field_elements()
                    .unwrap()
                    .into_iter()
                    .map(|fq| FqVar::new_witness(cs.clone(), || Ok(fq)).unwrap())
                    .collect::<Vec<FqVar>>()
            })
            .collect::<Vec<Vec<FqVar>>>();
        let output_note_vars = self
            .private
            .output_notes
            .map(|note| NoteVar::new_witness(cs.clone(), || Ok(note.clone())).unwrap());
        let input_note_proof_vars = self.private.input_notes_proofs.map(|auth_path| {
            Poseidon377MerklePathVar::new_witness(ark_relations::ns!(cs, "path_var"), || {
                Ok(auth_path)
            })
            .unwrap()
        });
        let setoff_var = AmountVar::new_witness(cs.clone(), || Ok(self.private.setoff_amount))?;
        let solver_ivk_var = {
            let ak_element_var: AuthorizationKeyVar =
                AuthorizationKeyVar::new_witness(cs.clone(), || Ok(self.private.solver_ak))?;
            let nk_var = NullifierKeyVar::new_witness(cs.clone(), || Ok(self.private.solver_nk))?;
            IncomingViewingKeyVar::derive(&nk_var, &ak_element_var)?
        };

        let mut expected_output_note_commitment_vars = vec![];
        for note in &self.private.input_notes {
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
        let input_note_vars = self
            .private
            .input_notes
            .map(|note| NoteVar::new_witness(cs.clone(), || Ok(note.clone())).unwrap());

        // Public inputs
        let output_note_commitment_vars = self
            .private
            .uncompressed_public
            .output_notes_commitments
            .map(|commitment| {
                StateCommitmentVar::new_input(cs.clone(), || Ok(commitment)).unwrap()
            });
        let nullifier_vars = self
            .private
            .uncompressed_public
            .nullifiers
            .map(|nullifier| NullifierVar::new_input(cs.clone(), || Ok(nullifier)).unwrap());
        let root_var =
            RootVar::new_input(cs.clone(), || Ok(self.private.uncompressed_public.root))?;
        let pub_inputs_hash_var = FqVar::new_input(cs.clone(), || Ok(self.public.pub_inputs_hash))?;
        let note_ciphertext_vars = self
            .private
            .uncompressed_public
            .note_ciphertexts
            .map(|ss_ct| CiphertextVar::new_input(cs.clone(), || Ok(ss_ct.clone())).unwrap());
        let ss_ciphertext_vars = self
            .private
            .uncompressed_public
            .ss_ciphertexts
            .map(|ss_ct| CiphertextVar::new_input(cs.clone(), || Ok(ss_ct.clone())).unwrap());
        let note_epk_vars = self
            .private
            .uncompressed_public
            .note_epks
            .map(|epk| PublicKeyVar::new_input(cs.clone(), || Ok(epk)).unwrap());

        // Constants
        let constants = SettlementProofConst::default();
        let leaf_crh_params_var =
            CRHParametersVar::new_constant(cs.clone(), &constants.leaf_crh_params)?;
        let two_to_one_crh_params_var =
            CRHParametersVar::new_constant(cs.clone(), &constants.two_to_one_crh_params)?;
        let zero_var = AmountVar::new_constant(cs.clone(), Amount::zero())?;

        // TODO: impl note well-formedness checks

        // Confirm public input hash integrity
        // Need to re-pad the FqVar values. TODO: Try avoiding these function calls
        let computed_hash_var = calculate_pub_hash_var(
            cs.clone(),
            &output_note_commitment_vars,
            &nullifier_vars,
            &root_var,
        )?;
        computed_hash_var.enforce_equal(&pub_inputs_hash_var)?;

        // Note commitment integrity check
        for (output_note_commitment_var, output_note_var) in output_note_commitment_vars
            .iter()
            .take(unpadded_len)
            .zip(output_note_vars.iter())
        {
            let note_commitment = output_note_var.commit()?;
            note_commitment.enforce_equal(output_note_commitment_var)?;
        }

        // Nullifier integrity check
        for (claimed_nullifier_var, note_var) in nullifier_vars
            .iter()
            .take(unpadded_len)
            .zip(input_note_vars.iter())
        {
            let nullifier_var = NullifierVar::derive(note_var)?;
            nullifier_var.enforce_equal(claimed_nullifier_var)?;
        }

        // verify merkle proofs
        for (input_note_var, input_note_proof_var) in input_note_vars
            .iter()
            .take(unpadded_len)
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

        for input_note_var in input_note_vars.windows(2).take(unpadded_len - 1)
        // stop before we get to pair where the second note is padded
        {
            let curr_creditor = &input_note_var[0].creditor;
            let next_debtor = &input_note_var[1].debtor;
            enforce_equal_addresses(curr_creditor, next_debtor)?;
        }
        let first_debtor = input_note_vars
            .first()
            .map(|n| &n.debtor)
            .ok_or(SynthesisError::Unsatisfiable)?;
        let last_creditor = input_note_vars
            .get(unpadded_len - 1)
            .map(|n| &n.creditor)
            .ok_or(SynthesisError::Unsatisfiable)?;
        enforce_equal_addresses(first_debtor, last_creditor)?;

        // fixme: Do we need to check there are >1 input notes?

        // setoff_amount > 0
        setoff_var
            .amount
            .enforce_cmp(&zero_var.amount, Ordering::Greater, false)?;

        // min_amount >= setoff_amount
        for input_note_var in input_note_vars.iter().take(unpadded_len) {
            input_note_var.value.amount.amount.enforce_cmp(
                &setoff_var.amount,
                Ordering::Greater,
                true,
            )?
        }

        // check output notes correspond to reduced input notes
        for (expected, claimed) in expected_output_note_commitment_vars
            .iter()
            .take(unpadded_len)
            .zip(output_note_commitment_vars.iter())
        {
            expected.enforce_equal(claimed)?;
        }

        // prove output notes were encrypted to same shared secret as input notes (or equivalently `ss_ciphertexts`)
        for (((ss_ciphertext_var, epk_var), output_note_ser_var), note_ciphertext_var) in
            ss_ciphertext_vars
                .iter()
                .take(unpadded_len)
                .zip(note_epk_vars.iter())
                .zip(output_note_ser_vars.iter())
                .zip(note_ciphertext_vars.iter())
        {
            // fixme
            // fn key_agreement(sk: FqVar, pk: ElementVar) -> Result<ElementVar, SynthesisError> {
            //     let sk_vars = sk.to_bits_le()?;
            //     pk.scalar_mul_le(sk_vars.to_bits_le()?.iter())
            // }

            let s_var = {
                let ss = solver_ivk_var.diversified_public(&epk_var.0)?;
                let s_tee_var = SharedSecretVar(ss);

                let plaintext_fq_var_vec = r1cs::ecies_decrypt(&s_tee_var, ss_ciphertext_var)?;
                let s_fq_var = plaintext_fq_var_vec.0.first().unwrap().clone();
                SharedSecretVar(ElementVar::decompress_from_field(s_fq_var)?)
            };

            let note_field_elements = PlaintextVar(output_note_ser_var.clone());
            let expected_note_ciphertext_var = r1cs::ecies_encrypt(&s_var, &note_field_elements)?;
            expected_note_ciphertext_var.enforce_equal(note_ciphertext_var)?;
        }

        Ok(())
    }
}

impl DummyWitness for SettlementCircuit<MAX_PROOF_INPUT_ARRAY_SIZE> {
    fn with_dummy_witness() -> Self {
        let seed_phrase_randomness_1 = SeedPhrase::from_randomness(&[b'f'; 32]);
        let sk_debtor =
            SpendKey::from_seed_phrase_bip44(seed_phrase_randomness_1, &Bip44Path::new(0));
        let fvk_debtor = sk_debtor.full_viewing_key();
        let ivk_debtor = fvk_debtor.incoming();
        let (d_addr, _dtk_d) = ivk_debtor.payment_address(0u32.into());

        let seed_phrase_randomness_2 = SeedPhrase::from_randomness(&[b'e'; 32]);
        let sk_creditor =
            SpendKey::from_seed_phrase_bip44(seed_phrase_randomness_2, &Bip44Path::new(0));
        let fvk_creditor = sk_creditor.full_viewing_key();
        let ivk_creditor = fvk_creditor.incoming();
        let (c_addr, _dtk_d) = ivk_creditor.payment_address(0u32.into());

        let d_c_inote_rseed = Rseed([1; 32]);
        let c_d_inote_rseed = Rseed([2; 32]);

        let value_to_send = "20upenumbra".parse().expect("valid value");
        let d_c_inote = Note::from_parts(
            d_addr.clone(),
            c_addr.clone(),
            value_to_send,
            d_c_inote_rseed,
        )
        .expect("should be able to create note");
        let d_c_inote_nul = Nullifier::derive(&d_c_inote);

        let c_d_inote = Note::from_parts(
            c_addr.clone(),
            d_addr.clone(),
            value_to_send,
            c_d_inote_rseed,
        )
        .expect("should be able to create note");
        let c_d_inote_nul = Nullifier::derive(&c_d_inote);

        let value_reduced = "0upenumbra".parse().expect("valid value");
        let d_c_onote = Note::from_parts(
            d_addr.clone(),
            c_addr.clone(),
            value_reduced,
            d_c_inote_rseed,
        )
        .expect("should be able to create note");
        let d_c_onote_comm = d_c_onote.commit();
        let c_d_onote = Note::from_parts(
            c_addr.clone(),
            d_addr.clone(),
            value_reduced,
            c_d_inote_rseed,
        )
        .expect("should be able to create note");
        let c_d_onote_comm = c_d_onote.commit();

        let constants = SettlementProofConst::default();
        let leaves: Vec<[Fq; 1]> = vec![[d_c_inote.commit().0], [c_d_inote.commit().0]];
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

        let s_addr = test_keys::ADDRESS_0.clone();
        let (d_c_onote_ct, d_c_ss_ct, d_c_e_pk) =
            encrypt_note_and_shared_secret(&d_c_inote, &d_c_onote, &c_addr, &s_addr).unwrap();
        let (c_d_onote_ct, c_d_ss_ct, c_d_e_pk) =
            encrypt_note_and_shared_secret(&c_d_inote, &c_d_onote, &d_addr, &s_addr).unwrap();

        let uncompressed_public = SettlementProofUncompressedPublic {
            output_notes_commitments: [d_c_onote_comm, c_d_onote_comm],
            nullifiers: [d_c_inote_nul, c_d_inote_nul],
            root: tree.root(),
            note_ciphertexts: [d_c_onote_ct, c_d_onote_ct],
            ss_ciphertexts: [d_c_ss_ct, c_d_ss_ct],
            note_epks: [d_c_e_pk, c_d_e_pk],
        };
        let public = uncompressed_public
            .clone()
            .padded()
            .unwrap()
            .compress_to_public();
        let private = SettlementProofPrivate {
            uncompressed_public,
            output_notes: [d_c_onote, c_d_onote],
            input_notes: [d_c_inote, c_d_inote],
            setoff_amount: Amount::from(20u8),
            input_notes_proofs: [input_auth_path_1, input_auth_path_2],
            solver_ak: *test_keys::FULL_VIEWING_KEY.spend_verification_key(),
            solver_nk: *test_keys::FULL_VIEWING_KEY.nullifier_key(),
        };

        SettlementCircuit::new(public, private.padded().unwrap()).unwrap()
    }
}

pub fn encrypt_note_and_shared_secret(
    inote: &Note,
    onote: &Note,
    c_addr: &Address,
    s_addr: &Address,
) -> anyhow::Result<(Ciphertext, Ciphertext, Public)> {
    // Derive ephemeral secret key.
    let e_sk = inote.rseed().derive_esk();

    // Encrypt the output note.
    let c_pk = c_addr.transmission_key();
    let d_c_ss = e_sk.key_agreement_with(c_pk)?;
    let d_c_ss_enc = Encoding(d_c_ss.0)
        .vartime_decompress()
        .map_err(|e| anyhow::anyhow!(e))?;
    let onote_ct = ecies_encrypt(d_c_ss_enc, onote.to_field_elements().unwrap())
        .map_err(|e| anyhow::anyhow!(e))?;

    // Encrypt the shared secret for the solver.
    let e_pk = e_sk.diversified_public(s_addr.diversified_generator());
    let s_pk = s_addr.transmission_key();
    let d_s_ss = e_sk.key_agreement_with(s_pk)?;
    let d_s_ss_enc = Encoding(d_s_ss.0)
        .vartime_decompress()
        .map_err(|e| anyhow::anyhow!(e))?;
    let d_c_ss_ct = ecies_encrypt(d_s_ss_enc, vec![d_c_ss_enc.vartime_compress_to_field()])?;

    Ok((onote_ct, d_c_ss_ct, e_pk))
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
        private: SettlementProofPrivate<MAX_PROOF_INPUT_ARRAY_SIZE>,
    ) -> anyhow::Result<Self> {
        let circuit = SettlementCircuit::new(public, private)?;
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
        public: SettlementProofUncompressedPublic<MAX_PROOF_INPUT_ARRAY_SIZE>,
    ) -> anyhow::Result<()> {
        // Check that the proof's public input hash matches the hash of inputs
        if public_inputs_hash
            != calculate_pub_hash(
                &public.output_notes_commitments,
                &public.nullifiers,
                &public.root,
            )
        {
            anyhow::bail!("Public inputs hash mismatch");
        }

        let proof =
            Proof::deserialize_compressed_unchecked(&self.0[..]).map_err(|e| anyhow::anyhow!(e))?;

        let public_inputs = vec![public_inputs_hash];

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

impl From<SettlementProof> for [u8; GROTH16_PROOF_LENGTH_BYTES] {
    fn from(value: SettlementProof) -> Self {
        value.0
    }
}

// Convenience conversion for the public inputs structure
impl<const N: usize> SettlementProofUncompressedPublic<N> {
    pub fn padded(
        self,
    ) -> anyhow::Result<SettlementProofUncompressedPublic<MAX_PROOF_INPUT_ARRAY_SIZE>> {
        Ok(SettlementProofUncompressedPublic {
            output_notes_commitments: pad_to_fixed_size(&self.output_notes_commitments)?,
            nullifiers: pad_to_fixed_size(&self.nullifiers)?,
            root: self.root,
            note_ciphertexts: pad_to_fixed_size(&self.note_ciphertexts)?,
            ss_ciphertexts: pad_to_fixed_size(&self.ss_ciphertexts)?,
            note_epks: pad_to_fixed_size(&self.note_epks)?,
        })
    }
}

impl SettlementProofUncompressedPublic<MAX_PROOF_INPUT_ARRAY_SIZE> {
    pub fn compress_to_public(&self) -> SettlementProofPublic {
        let pub_inputs_hash =
            calculate_pub_hash(&self.output_notes_commitments, &self.nullifiers, &self.root);
        SettlementProofPublic { pub_inputs_hash }
    }
}

// Convenience conversion for the private proof structure.
impl<const N: usize> SettlementProofPrivate<N> {
    pub fn padded(self) -> anyhow::Result<SettlementProofPrivate<MAX_PROOF_INPUT_ARRAY_SIZE>> {
        Ok(SettlementProofPrivate {
            uncompressed_public: self.uncompressed_public.padded()?,
            output_notes: pad_to_fixed_size(&self.output_notes)?,
            input_notes: pad_to_fixed_size(&self.input_notes)?,
            input_notes_proofs: pad_to_fixed_size(&self.input_notes_proofs)?,
            setoff_amount: self.setoff_amount,
            solver_ak: self.solver_ak,
            solver_nk: self.solver_nk,
        })
    }
}

#[cfg(test)]
mod tests {
    use arkworks_merkle_tree::poseidontree::Poseidon377MerkleTree;
    use decaf377::{Encoding, Fq};
    use decaf377_ka::{Secret, SharedSecret};
    use penumbra_asset::{asset, Value};
    use penumbra_keys::keys::{Bip44Path, SeedPhrase, SpendKey};
    use penumbra_keys::{test_keys, Address};
    use penumbra_num::Amount;
    use penumbra_shielded_pool::Rseed;
    use proptest::prelude::*;
    use rand_core::OsRng;

    use crate::encryption::{ecies_decrypt, ecies_encrypt};
    use crate::note::{commitment, Note};
    use crate::nullifier::Nullifier;
    use crate::settlement::proof::{
        check_circuit_satisfaction, check_satisfaction, encrypt_note_and_shared_secret,
        SettlementProofConst, SettlementProofUncompressedPublic,
    };
    use crate::settlement::{
        proof::MAX_PROOF_INPUT_ARRAY_SIZE, SettlementProofPrivate, SettlementProofPublic,
    };

    fn fq_strategy() -> BoxedStrategy<Fq> {
        any::<[u8; 32]>()
            .prop_map(|bytes| Fq::from_le_bytes_mod_order(&bytes[..]))
            .boxed()
    }

    fn address_from_seed(seed_phrase_randomness: &[u8], index: u32) -> Address {
        let seed_phrase = SeedPhrase::from_randomness(seed_phrase_randomness);
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
            rseed_randomness_1 in any::<[u8; 32]>(),
            rseed_randomness_2 in any::<[u8; 32]>(),
            amount in 2u64.., asset_id64 in any::<u64>(),
            address_index_1 in any::<u32>(),
            address_index_2 in any::<u32>()
        ) -> (SettlementProofPublic, SettlementProofPrivate<MAX_PROOF_INPUT_ARRAY_SIZE>) {
            let d_addr = address_from_seed(&seed_phrase_randomness_1, address_index_1);
            let c_addr = address_from_seed(&seed_phrase_randomness_2, address_index_2);
            let d_c_inote_rseed = Rseed(rseed_randomness_1);
            let c_d_inote_rseed = Rseed(rseed_randomness_2);

            let value_to_send = Value {
                amount: Amount::from(amount),
                asset_id: asset::Id(Fq::from(asset_id64)),
            };
            let d_c_inote = Note::from_parts(
                d_addr.clone(),
                c_addr.clone(),
                value_to_send,
                d_c_inote_rseed,
            ).expect("should be able to create note");
            let d_c_inote_nul = Nullifier::derive(&d_c_inote);

            let c_d_inote = Note::from_parts(
                c_addr.clone(),
                d_addr.clone(),
                value_to_send,
                c_d_inote_rseed,
            ).expect("should be able to create note");
            let c_d_inote_nul = Nullifier::derive(&c_d_inote);

            let setoff_amount = amount;
            let value_reduced = Value {
                amount: Amount::from(amount - setoff_amount),
                asset_id: asset::Id(Fq::from(asset_id64)),
            };
            let d_c_onote = Note::from_parts(
                d_addr.clone(),
                c_addr.clone(),
                value_reduced,
                d_c_inote_rseed,
            ).expect("should be able to create note");
            let d_c_onote_comm = d_c_onote.commit();
            let c_d_onote = Note::from_parts(
                c_addr.clone(),
                d_addr.clone(),
                value_reduced,
                c_d_inote_rseed,
            ).expect("should be able to create note");
            let c_d_onote_comm = c_d_onote.commit();

            let constants = SettlementProofConst::default();
            let leaves: Vec<[Fq; 1]> = vec![[d_c_inote.commit().0], [c_d_inote.commit().0]];
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

            let s_addr = test_keys::ADDRESS_0.clone();
            let (d_c_onote_ct, d_c_ss_ct, d_c_e_pk) = encrypt_note_and_shared_secret(
                &d_c_inote, &d_c_onote, &c_addr, &s_addr
            ).unwrap();
            let (c_d_onote_ct, c_d_ss_ct, c_d_e_pk) = encrypt_note_and_shared_secret(
                &c_d_inote, &c_d_onote, &d_addr, &s_addr
            ).unwrap();

            let uncompressed_public = SettlementProofUncompressedPublic {
                output_notes_commitments: [d_c_onote_comm, c_d_onote_comm],
                nullifiers: [d_c_inote_nul, c_d_inote_nul],
                root: tree.root(),
                note_ciphertexts: [d_c_onote_ct, c_d_onote_ct],
                ss_ciphertexts: [d_c_ss_ct, c_d_ss_ct],
                note_epks: [d_c_e_pk, c_d_e_pk],
            };
            let public = uncompressed_public.clone().padded().unwrap().compress_to_public();
            let private = SettlementProofPrivate {
                uncompressed_public,
                output_notes: [d_c_onote, c_d_onote],
                input_notes: [d_c_inote, c_d_inote],
                setoff_amount: Amount::from(setoff_amount),
                input_notes_proofs: [input_auth_path_1, input_auth_path_2],
                solver_ak: *test_keys::FULL_VIEWING_KEY.spend_verification_key(),
                solver_nk: *test_keys::FULL_VIEWING_KEY.nullifier_key(),
            };

            (public, private.padded().unwrap())
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
        // This strategy generates a settlement statement, but then replaces the note commitment
        // with one generated using an invalid note blinding factor.
        fn arb_invalid_settlement_note_commitment_integrity()(
            seed_phrase_randomness_1 in any::<[u8; 32]>(),
            seed_phrase_randomness_2 in any::<[u8; 32]>(),
            rseed_randomness_1 in any::<[u8; 32]>(),
            rseed_randomness_2 in any::<[u8; 32]>(),
            amount in 2u64.., asset_id64 in any::<u64>(),
            address_index_1 in any::<u32>(),
            address_index_2 in any::<u32>(),
            incorrect_note_blinding in fq_strategy()
        ) -> (SettlementProofPublic, SettlementProofPrivate<MAX_PROOF_INPUT_ARRAY_SIZE>) {
            let d_addr = address_from_seed(&seed_phrase_randomness_1, address_index_1);
            let c_addr = address_from_seed(&seed_phrase_randomness_2, address_index_2);
            let d_c_inote_rseed = Rseed(rseed_randomness_1);
            let c_d_inote_rseed = Rseed(rseed_randomness_2);

            let value_to_send = Value {
                amount: Amount::from(amount),
                asset_id: asset::Id(Fq::from(asset_id64)),
            };
            let d_c_inote = Note::from_parts(
                d_addr.clone(),
                c_addr.clone(),
                value_to_send,
                d_c_inote_rseed,
            ).expect("should be able to create note");
            let d_c_inote_nul = Nullifier::derive(&d_c_inote);

            let c_d_inote = Note::from_parts(
                c_addr.clone(),
                d_addr.clone(),
                value_to_send,
                c_d_inote_rseed,
            ).expect("should be able to create note");
            let c_d_inote_nul = Nullifier::derive(&c_d_inote);

            let setoff_amount = amount;
            let value_reduced = Value {
                amount: Amount::from(amount - setoff_amount),
                asset_id: asset::Id(Fq::from(asset_id64)),
            };
            let d_c_onote = Note::from_parts(
                d_addr.clone(),
                c_addr.clone(),
                value_reduced,
                d_c_inote_rseed,
            ).expect("should be able to create note");
            let d_c_onote_comm = d_c_onote.commit();
            let c_d_onote = Note::from_parts(
                c_addr.clone(),
                d_addr.clone(),
                value_reduced,
                c_d_inote_rseed,
            ).expect("should be able to create note");
            let incorrect_c_d_onote_comm = commitment(
                incorrect_note_blinding,
                value_to_send,
                c_d_onote.diversified_generator(),
                c_d_onote.transmission_key_s(),
                c_d_onote.clue_key(),
                *c_d_onote.creditor().transmission_key_s()
            );
            let constants = SettlementProofConst::default();
            let leaves: Vec<[Fq; 1]> = vec![[d_c_inote.commit().0], [c_d_inote.commit().0]];
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

            let s_addr = test_keys::ADDRESS_0.clone();
            let (d_c_onote_ct, d_c_ss_ct, d_c_e_pk) = encrypt_note_and_shared_secret(
                &d_c_inote, &d_c_onote, &c_addr, &s_addr
            ).unwrap();
            let (c_d_onote_ct, c_d_ss_ct, c_d_e_pk) = encrypt_note_and_shared_secret(
                &c_d_inote, &c_d_onote, &d_addr, &s_addr
            ).unwrap();

            let uncompressed_public = SettlementProofUncompressedPublic {
                output_notes_commitments: [d_c_onote_comm, incorrect_c_d_onote_comm],
                nullifiers: [d_c_inote_nul, c_d_inote_nul],
                root: tree.root(),
                note_ciphertexts: [d_c_onote_ct, c_d_onote_ct],
                ss_ciphertexts: [d_c_ss_ct, c_d_ss_ct],
                note_epks: [d_c_e_pk, c_d_e_pk],
            };
            let bad_public = uncompressed_public.clone().padded().unwrap().compress_to_public();
            let private = SettlementProofPrivate {
                uncompressed_public,
                output_notes: [d_c_onote, c_d_onote],
                input_notes: [d_c_inote, c_d_inote],
                setoff_amount: Amount::from(setoff_amount),
                input_notes_proofs: [input_auth_path_1, input_auth_path_2],
                solver_ak: *test_keys::FULL_VIEWING_KEY.spend_verification_key(),
                solver_nk: *test_keys::FULL_VIEWING_KEY.nullifier_key(),
            };

            (bad_public, private.padded().unwrap())
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

    #[test]
    fn test_key_enc() {
        let s1 = Secret::new(&mut OsRng);
        let s2 = Secret::new(&mut OsRng);
        let p2 = s2.public();
        let s3 = Secret::new(&mut OsRng);
        let p3 = s3.public();

        let ss_12 = s1.key_agreement_with(&p2).unwrap();
        let ss_13 = s1.key_agreement_with(&p3).unwrap();
        let ss_elm_12 = Encoding(ss_12.0).vartime_decompress().unwrap();
        let ss_elm_13 = Encoding(ss_13.0).vartime_decompress().unwrap();
        let d_c_ss_ct2 =
            ecies_encrypt(ss_elm_13, vec![ss_elm_12.vartime_compress_to_field()]).unwrap();
        let ss_elm_plaintext_12 = ecies_decrypt(ss_elm_13, d_c_ss_ct2).unwrap();

        let ss_elm_12_dec = Encoding(ss_elm_plaintext_12[0].to_bytes())
            .vartime_decompress()
            .unwrap();
        assert_eq!(ss_elm_12_dec, ss_elm_12)
    }

    #[test]
    fn test_key_enc_penumbra() {
        // 1. debtor performs DHKE with creditor to obtain the debtor-creditor-shared-secret (i.e. `d_c_ss`)
        let e_sk = Rseed::generate(&mut OsRng).derive_esk();
        let c_addr = address_from_seed(&[2; 32], 2);
        let c_pk = c_addr.transmission_key();
        let d_c_ss = e_sk.key_agreement_with(c_pk).unwrap();
        let d_c_ss_enc = Encoding(d_c_ss.0).vartime_decompress().unwrap();

        // 2. debtor encrypts note with `d_c_ss` (not shown here)

        // 3. debtor performs DHKE with solver to obtain the debtor-solver-shared-secret (i.e. `d_s_ss`)
        let s_addr = test_keys::ADDRESS_0.clone();
        let s_pk = s_addr.transmission_key();
        let d_s_ss = e_sk.key_agreement_with(s_pk).unwrap();
        let d_s_ss_enc = Encoding(d_s_ss.0).vartime_decompress().unwrap();

        // 4. debtor encrypts `d_c_ss` to solver (i.e. using `d_s_ss`)
        let d_c_ss_ct =
            ecies_encrypt(d_s_ss_enc, vec![d_c_ss_enc.vartime_compress_to_field()]).unwrap();

        // 5. debtor sends `e_pk` and `d_c_ss_ct` to solver (over the blockchain)
        let e_pk = e_sk.diversified_public(s_addr.diversified_generator());

        // 6. solver performs DHKE using `e_pk` to obtain the debtor-solver-shared-secret (i.e. `s_d_ss`)
        let s_ivk = test_keys::FULL_VIEWING_KEY.incoming();
        let s_d_ss = s_ivk.key_agreement_with(&e_pk).unwrap();
        assert_eq!(s_d_ss, d_s_ss);

        // 7. solver decrypts `d_c_ss_ct` to obtain `d_c_ss`
        let s_d_ss_enc = Encoding(s_d_ss.0).vartime_decompress().unwrap();
        let d_c_ss_pt = ecies_decrypt(s_d_ss_enc, d_c_ss_ct).unwrap();
        let d_c_ss_dec = Encoding(d_c_ss_pt[0].to_bytes())
            .vartime_decompress()
            .unwrap();
        assert_eq!(d_c_ss_dec, d_c_ss_enc);
        assert_eq!(
            d_c_ss,
            SharedSecret::try_from(d_c_ss_pt[0].to_bytes()).unwrap()
        );
    }

    #[test]
    fn test_dhke() {
        let e_sk = Rseed::generate(&mut OsRng).derive_esk();
        let s_addr = test_keys::ADDRESS_0.clone();
        let s_pk = s_addr.transmission_key();
        let d_s_ss = e_sk.key_agreement_with(s_pk).unwrap();
        let e_pk = e_sk.diversified_public(s_addr.diversified_generator());
        let s_ivk = test_keys::FULL_VIEWING_KEY.incoming();
        let s_d_ss = s_ivk.key_agreement_with(&e_pk).unwrap();
        assert_eq!(s_d_ss, d_s_ss);
    }
}
