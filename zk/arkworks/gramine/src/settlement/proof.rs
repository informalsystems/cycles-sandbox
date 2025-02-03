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
use decaf377::{Bls12_377, Encoding, Fq};
use decaf377_fmd as fmd;
use decaf377_ka as ka;
use decaf377_ka::Public;
use decaf377_rdsa::{SpendAuth, VerificationKey};
use penumbra_asset::Value;
use penumbra_keys::keys::{
    AuthorizationKeyVar, IncomingViewingKeyVar, NullifierKey, NullifierKeyVar,
};
use penumbra_keys::{keys::Diversifier, test_keys, Address, FullViewingKey};
use penumbra_num::{Amount, AmountVar};
use penumbra_proof_params::{DummyWitness, VerifyingKeyExt, GROTH16_PROOF_LENGTH_BYTES};
use penumbra_proto::{penumbra::core::component::shielded_pool::v1 as pb, DomainType};
use penumbra_shielded_pool::{note, Rseed};
use penumbra_tct::r1cs::StateCommitmentVar;
use poseidon377::{RATE_1_PARAMS, RATE_2_PARAMS};
use poseidon_parameters::v1::Matrix;

use crate::encryption::r1cs::{CiphertextVar, PublicKeyVar};
use crate::encryption::{ecies_decrypt, ecies_encrypt, Ciphertext};
use crate::note::r1cs::enforce_equal_addresses;
use crate::note::{r1cs::NoteVar, Note};
use crate::nullifier::{Nullifier, NullifierVar};

/// The public input for an [`SettlementProof`].
#[derive(Clone, Debug)]
pub struct SettlementProofPublic {
    /// A hiding commitment to output notes.
    pub output_notes_commitments: Vec<note::StateCommitment>,
    /// Nullifiers for input notes.
    pub nullifiers: Vec<Nullifier>,
    /// These are the public inputs to the circuit merkle tree verification circuit
    pub root: Root,
    /// Note ciphertexts encrypted using the note's esk.
    pub note_ciphertexts: Vec<Ciphertext>,
    /// Shared secret ciphertexts encrypted using the note's shared secret.
    pub ss_ciphertexts: Vec<Ciphertext>,
    /// Note ephemeral public keys.
    pub note_epks: Vec<Public>,
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

    // prove output notes were encrypted to same shared secret as input notes (or equivalently ss_ciphertexts)
    let solver_ivk = FullViewingKey::from_components(private.solver_ak, private.solver_nk)
        .incoming()
        .clone();
    let mut shared_secrets = vec![];
    for (ss_ciphertext, epk) in public.ss_ciphertexts.iter().zip(public.note_epks.iter()) {
        let s_tee = {
            let ss = solver_ivk.key_agreement_with(epk)?;
            Encoding(ss.0)
                .vartime_decompress()
                .map_err(|e| anyhow::anyhow!(e))?
        };
        let s = {
            let s_plaintext_fq_vec = ecies_decrypt(s_tee.clone(), ss_ciphertext.clone())?;
            let s_fq = s_plaintext_fq_vec.first().unwrap();
            let s = Encoding(s_fq.to_bytes()).vartime_decompress().unwrap();
            s
        };
        shared_secrets.push(s);
    }
    for ((output_note, shared_secret), expected_ciphertext) in private
        .output_notes
        .iter()
        .zip(shared_secrets.iter())
        .zip(public.note_ciphertexts.iter())
    {
        let output_note = output_note.to_field_elements().unwrap();
        let ciphertext = ecies_encrypt(shared_secret.clone(), output_note)?;
        anyhow::ensure!(&ciphertext == expected_ciphertext);
    }

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
        let output_note_commitment_vars = self
            .public
            .output_notes_commitments
            .iter()
            .map(|commitment| StateCommitmentVar::new_input(cs.clone(), || Ok(*commitment)))
            .collect::<Result<Vec<_>, _>>()?;
        let nullifier_vars = self
            .public
            .nullifiers
            .iter()
            .map(|nullifier| NullifierVar::new_input(cs.clone(), || Ok(*nullifier)))
            .collect::<Result<Vec<_>, _>>()?;
        let root_var = RootVar::new_input(cs.clone(), || Ok(self.public.root))?;

        // Constants
        let constants = SettlementProofConst::default();
        let leaf_crh_params_var =
            CRHParametersVar::new_constant(cs.clone(), &constants.leaf_crh_params)?;
        let two_to_one_crh_params_var =
            CRHParametersVar::new_constant(cs.clone(), &constants.two_to_one_crh_params)?;
        let zero_var = AmountVar::new_constant(cs.clone(), Amount::zero())?;

        // TODO: impl note well-formedness checks

        // Note commitment integrity check
        for (output_note_commitment_var, output_note_var) in output_note_commitment_vars
            .iter()
            .zip(output_note_vars.iter())
        {
            let note_commitment = output_note_var.commit()?;
            note_commitment.enforce_equal(output_note_commitment_var)?;
        }

        // Nullifier integrity check
        for (claimed_nullifier_var, note_var) in nullifier_vars.iter().zip(input_note_vars.iter()) {
            let nullifier_var = NullifierVar::derive(note_var)?;
            nullifier_var.enforce_equal(claimed_nullifier_var)?;
        }

        for (input_note_var, input_note_proof_var) in
            input_note_vars.iter().zip(input_note_proof_vars.iter())
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

        let public = SettlementProofPublic {
            output_notes_commitments: vec![note.commit()],
            nullifiers: vec![Nullifier::derive(&note)],
            root: tree.root(),
            note_ciphertexts: vec![],
            ss_ciphertexts: vec![],
            note_epks: vec![],
        };
        let private = SettlementProofPrivate {
            output_notes: vec![note.clone()],
            input_notes: vec![note],
            setoff_amount: Amount::zero(),
            input_notes_proofs: vec![auth_path],
            solver_ak: test_keys::FULL_VIEWING_KEY.spend_verification_key().clone(),
            solver_nk: test_keys::FULL_VIEWING_KEY.nullifier_key().clone(),
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
    use crate::encryption::{ecies_decrypt, ecies_encrypt};
    use crate::note::{commitment, Note};
    use crate::nullifier::Nullifier;
    use crate::settlement::proof::{
        check_circuit_satisfaction, check_satisfaction, SettlementProofConst,
    };
    use crate::settlement::{SettlementProofPrivate, SettlementProofPublic};
    use ark_ff::ToConstraintField;
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
            rseed_randomness_1 in any::<[u8; 32]>(),
            rseed_randomness_2 in any::<[u8; 32]>(),
            amount in 2u64.., asset_id64 in any::<u64>(),
            address_index_1 in any::<u32>(),
            address_index_2 in any::<u32>()
        ) -> (SettlementProofPublic, SettlementProofPrivate) {
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

            // Encrypt output notes
            let e_sk = d_c_inote_rseed.derive_esk();
            let c_pk = c_addr.transmission_key();
            let d_c_ss = e_sk.key_agreement_with(c_pk).unwrap();
            let d_c_ss_enc = Encoding(d_c_ss.0).vartime_decompress().unwrap();
            let d_c_onote_ct = ecies_encrypt(d_c_ss_enc, d_c_onote.to_field_elements().unwrap()).unwrap();

            // Encrypt shared secret to solver
            let s_addr = test_keys::ADDRESS_0.clone();
            let e_pk = e_sk.diversified_public(&s_addr.diversified_generator());
            let s_pk = s_addr.transmission_key();
            let d_s_ss = e_sk.key_agreement_with(s_pk).unwrap();
            let d_s_ss_enc = Encoding(d_s_ss.0).vartime_decompress().unwrap();
            let d_c_ss_ct = ecies_encrypt(d_s_ss_enc, vec![d_c_ss_enc.vartime_compress_to_field()]).unwrap();

            let public = SettlementProofPublic {
                output_notes_commitments: vec![d_c_onote_comm, c_d_onote_comm],
                nullifiers: vec![d_c_inote_nul, c_d_inote_nul],
                root: tree.root(),
                note_ciphertexts: vec![d_c_onote_ct],
                ss_ciphertexts: vec![d_c_ss_ct],
                note_epks: vec![e_pk],
            };
            let private = SettlementProofPrivate {
                output_notes: vec![d_c_onote, c_d_onote],
                input_notes: vec![d_c_inote, c_d_inote],
                setoff_amount: Amount::from(setoff_amount),
                input_notes_proofs: vec![input_auth_path_1, input_auth_path_2],
                solver_ak: test_keys::FULL_VIEWING_KEY.spend_verification_key().clone(),
                solver_nk: test_keys::FULL_VIEWING_KEY.nullifier_key().clone(),
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
            let d_addr = address_from_seed(&seed_phrase_randomness_1, address_index_1);
            let c_addr = address_from_seed(&seed_phrase_randomness_2, address_index_2);

            let value_to_send = Value {
                amount: Amount::from(amount),
                asset_id: asset::Id(Fq::from(asset_id64)),
            };
            let d_c_inote = Note::from_parts(
                d_addr.clone(),
                c_addr.clone(),
                value_to_send,
                Rseed(rseed_randomness),
            ).expect("should be able to create note");
            let d_c_inote_nul = Nullifier::derive(&d_c_inote);

            let c_d_inote = Note::from_parts(
                c_addr.clone(),
                d_addr.clone(),
                value_to_send,
                Rseed(rseed_randomness),
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
                Rseed(rseed_randomness),
            ).expect("should be able to create note");
            let d_c_onote_comm = d_c_onote.commit();
            let c_d_onote = Note::from_parts(
                c_addr,
                d_addr,
                value_reduced,
                Rseed(rseed_randomness),
            ).expect("should be able to create note");
            let incorrect_c_d_onote_comm = commitment(
                incorrect_note_blinding,
                value_to_send,
                c_d_onote.diversified_generator(),
                c_d_onote.transmission_key_s(),
                c_d_onote.clue_key(),
                c_d_onote.creditor().transmission_key_s().clone()
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

            let bad_public = SettlementProofPublic {
                output_notes_commitments: vec![d_c_onote_comm, incorrect_c_d_onote_comm],
                nullifiers: vec![d_c_inote_nul, c_d_inote_nul],
                root: tree.root(),
                note_ciphertexts: vec![],
                ss_ciphertexts: vec![],
                note_epks: vec![],
            };
            let private = SettlementProofPrivate {
                output_notes: vec![d_c_onote, c_d_onote],
                input_notes: vec![d_c_inote, c_d_inote],
                setoff_amount: Amount::from(setoff_amount),
                input_notes_proofs: vec![input_auth_path_1, input_auth_path_2],
                solver_ak: test_keys::FULL_VIEWING_KEY.spend_verification_key().clone(),
                solver_nk: test_keys::FULL_VIEWING_KEY.nullifier_key().clone(),
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
