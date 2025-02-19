use base64::prelude::*;
use std::str::FromStr;

use anyhow::Result;
use ark_groth16::r1cs_to_qap::LibsnarkReduction;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use decaf377::{Bls12_377, Encoding, Fq, Fr};
use decaf377_rdsa::{SpendAuth, VerificationKey};

use ark_ff::ToConstraintField;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey};
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use decaf377_ka::{Public, Secret};
use penumbra_proto::{penumbra::core::component::shielded_pool::v1 as pb, DomainType};
use penumbra_tct::r1cs::StateCommitmentVar;

use crate::encryption::r1cs::{CiphertextVar, PlaintextVar, PublicKeyVar, SharedSecretVar};
use crate::encryption::{ecies_encrypt, r1cs, Ciphertext};
use crate::note::{r1cs::NoteVar, Note};
use penumbra_asset::Value;
use penumbra_keys::keys::{
    AuthorizationKeyVar, Bip44Path, IncomingViewingKeyVar, NullifierKey, NullifierKeyVar,
    RandomizedVerificationKey, SeedPhrase, SpendAuthRandomizerVar, SpendKey,
};
use penumbra_proof_params::{DummyWitness, VerifyingKeyExt, GROTH16_PROOF_LENGTH_BYTES};
use penumbra_shielded_pool::{note::StateCommitment, Rseed};

/// The public input for an [`OutputProof`].
#[derive(Clone, Debug)]
pub struct OutputProofPublic {
    /// A hiding commitment to the note.
    pub note_commitment: StateCommitment,
    /// the randomized verification spend key.
    pub rk: VerificationKey<SpendAuth>,
    /// Note ciphertext encrypted using the note's esk.
    pub note_ciphertext: Ciphertext,
    /// Ephemeral public key.
    pub e_pk: Public,
}

/// The private input for an [`OutputProof`].
#[derive(Clone, Debug)]
pub struct OutputProofPrivate {
    /// The note being created.
    pub note: Note,
    /// The randomizer used for generating the randomized spend auth key.
    pub spend_auth_randomizer: Fr,
    /// The spend authorization key.
    pub ak: VerificationKey<SpendAuth>,
    /// The nullifier deriving key.
    // We only need this to check that the rk matches the note being committed to
    pub nk: NullifierKey,
    /// Ephemeral secret key.
    pub e_sk: Secret,
}

#[cfg(test)]
fn check_satisfaction(public: &OutputProofPublic, private: &OutputProofPrivate) -> Result<()> {
    use penumbra_keys::FullViewingKey;

    if private.note.diversified_generator() == decaf377::Element::default() {
        anyhow::bail!("diversified generator is identity");
    }

    let note_commitment = private.note.commit();
    if note_commitment != public.note_commitment {
        anyhow::bail!("note commitment did not match public input");
    }

    let rk = private.ak.randomize(&private.spend_auth_randomizer);
    if rk != public.rk {
        anyhow::bail!("randomized spend auth key did not match public input");
    }

    let fvk = FullViewingKey::from_components(private.ak, private.nk);
    let ivk = fvk.incoming();
    let transmission_key = ivk.diversified_public(&private.note.diversified_generator());
    if transmission_key != *private.note.transmission_key() {
        anyhow::bail!("transmission key did not match note");
    }

    if private.note.diversified_generator() == decaf377::Element::default() {
        anyhow::bail!("diversified generator is identity");
    }

    if private.ak.is_identity() {
        anyhow::bail!("ak is identity");
    }

    // Check encryption integrity
    let computed_epk = private
        .e_sk
        .diversified_public(private.note.creditor().diversified_generator());
    anyhow::ensure!(computed_epk == public.e_pk);
    let ss_elem = {
        let ss = private
            .e_sk
            .key_agreement_with(private.note.creditor().transmission_key())?;
        Encoding(ss.0)
            .vartime_decompress()
            .map_err(|e| anyhow::anyhow!(e))?
    };
    let note_field_elements = private.note.to_field_elements().unwrap();
    let computed_ciphertext = ecies_encrypt(ss_elem, note_field_elements)?;
    anyhow::ensure!(computed_ciphertext == *public.note_ciphertext);

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
        let spend_auth_randomizer_var = SpendAuthRandomizerVar::new_witness(cs.clone(), || {
            Ok(self.private.spend_auth_randomizer)
        })?;
        // Note: in the allocation of `AuthorizationKeyVar` we check it is not identity.
        let ak_element_var: AuthorizationKeyVar =
            AuthorizationKeyVar::new_witness(cs.clone(), || Ok(self.private.ak))?;
        let nk_var = NullifierKeyVar::new_witness(cs.clone(), || Ok(self.private.nk))?;
        let note_fq_var = PlaintextVar::new_witness(cs.clone(), || {
            self.private
                .note
                .to_field_elements()
                .ok_or(SynthesisError::Unsatisfiable)
        })?;
        let e_sk_var = UInt8::new_witness_vec(cs.clone(), &self.private.e_sk.to_bytes())?;

        // Public inputs
        let claimed_note_commitment =
            StateCommitmentVar::new_input(cs.clone(), || Ok(self.public.note_commitment))?;
        let rk_var = RandomizedVerificationKey::new_input(cs.clone(), || Ok(self.public.rk))?;
        let note_ciphertext_var =
            CiphertextVar::new_input(cs.clone(), || Ok(self.public.note_ciphertext))?;
        let e_pk_var = PublicKeyVar::new_input(cs.clone(), || Ok(self.public.e_pk))?;

        // Note commitment integrity
        let note_commitment = note_var.commit()?;
        note_commitment.enforce_equal(&claimed_note_commitment)?;

        // Check integrity of randomized verification key.
        let computed_rk_var = ak_element_var.randomize(&spend_auth_randomizer_var)?;
        computed_rk_var.enforce_equal(&rk_var)?;

        // Check integrity of diversified address.
        let ivk = IncomingViewingKeyVar::derive(&nk_var, &ak_element_var)?;
        let computed_transmission_key =
            ivk.diversified_public(&note_var.diversified_generator())?;
        computed_transmission_key.enforce_equal(&note_var.transmission_key())?;

        // Check encryption integrity
        let esk_vars = e_sk_var.to_bits_le()?;
        let computed_epk_var = note_var
            .creditor
            .diversified_generator()
            .scalar_mul_le(esk_vars.to_bits_le()?.iter())?;
        computed_epk_var.enforce_equal(&e_pk_var.0)?;

        let ss_var = SharedSecretVar(
            note_var
                .creditor
                .transmission_key()
                .scalar_mul_le(esk_vars.to_bits_le()?.iter())?,
        );
        let computed_note_ciphertext_var = r1cs::ecies_encrypt(&ss_var, &note_fq_var)?;
        computed_note_ciphertext_var.enforce_equal(&note_ciphertext_var)?;

        Ok(())
    }
}

impl DummyWitness for OutputCircuit {
    fn with_dummy_witness() -> Self {
        let seed_phrase_debtor = SeedPhrase::from_randomness(&[b'f'; 32]);
        let sk_debtor = SpendKey::from_seed_phrase_bip44(seed_phrase_debtor, &Bip44Path::new(0));
        let fvk_debtor = sk_debtor.full_viewing_key();
        let ivk_debtor = fvk_debtor.incoming();
        let (address_debtor, _dtk_d) = ivk_debtor.payment_address(0u32.into());

        let spend_auth_randomizer = Fr::from(1u64);
        let rsk_debtor = sk_debtor.spend_auth_key().randomize(&spend_auth_randomizer);
        let rk_debtor: VerificationKey<SpendAuth> = rsk_debtor.into();
        let nk_debtor = *sk_debtor.nullifier_key();
        let ak_debtor = sk_debtor.spend_auth_key().into();

        let seed_phrase_creditor = SeedPhrase::from_randomness(&[b'e'; 32]);
        let sk_creditor =
            SpendKey::from_seed_phrase_bip44(seed_phrase_creditor, &Bip44Path::new(0));
        let fvk_creditor = sk_creditor.full_viewing_key();
        let ivk_creditor = fvk_creditor.incoming();
        let (address_creditor, _dtk_d) = ivk_creditor.payment_address(0u32.into());

        let note = Note::from_parts(
            address_debtor,
            address_creditor.clone(),
            Value::from_str("1upenumbra").expect("valid value"),
            Rseed([1u8; 32]),
        )
        .expect("can make a note");

        // Derive ephemeral secret key.
        let e_sk = note.rseed().derive_esk();

        // Encrypt the output note.
        let c_pk = address_creditor.transmission_key();
        let d_c_ss = e_sk.key_agreement_with(c_pk).unwrap();
        let d_c_ss_enc = Encoding(d_c_ss.0).vartime_decompress().unwrap();
        let note_ciphertext = ecies_encrypt(d_c_ss_enc, note.to_field_elements().unwrap()).unwrap();
        let e_pk = e_sk.diversified_public(address_creditor.diversified_generator());

        let public = OutputProofPublic {
            note_commitment: note.commit(),
            rk: rk_debtor,
            note_ciphertext,
            e_pk,
        };
        let private = OutputProofPrivate {
            note,
            spend_auth_randomizer,
            ak: ak_debtor,
            nk: nk_debtor,
            e_sk,
        };
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
        let element_rk = decaf377::Encoding(public.rk.to_bytes())
            .vartime_decompress()
            .map_err(|_| anyhow::anyhow!("could not decompress element points"))?;
        public_inputs.extend(
            element_rk
                .to_field_elements()
                .ok_or_else(|| anyhow::anyhow!("rk is not a valid field element"))?,
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

impl From<OutputProof> for [u8; GROTH16_PROOF_LENGTH_BYTES] {
    fn from(value: OutputProof) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::note::{commitment, Note};

    use decaf377::Fq;
    use penumbra_asset::{asset, Value};
    use penumbra_keys::keys::{Bip44Path, SeedPhrase, SpendKey};
    use penumbra_keys::Address;
    use penumbra_num::Amount;
    use proptest::prelude::*;

    fn fq_strategy() -> BoxedStrategy<Fq> {
        any::<[u8; 32]>()
            .prop_map(|bytes| Fq::from_le_bytes_mod_order(&bytes[..]))
            .boxed()
    }

    fn addr_from_sk(sk: &SpendKey, index: u32) -> Address {
        let fvk = sk.full_viewing_key();
        let ivk = fvk.incoming();
        ivk.payment_address(index.into()).0
    }

    fn sk_from_seed(seed_phrase_randomness: &[u8]) -> SpendKey {
        let seed_phrase = SeedPhrase::from_randomness(seed_phrase_randomness);
        SpendKey::from_seed_phrase_bip44(seed_phrase, &Bip44Path::new(0))
    }

    prop_compose! {
        fn arb_valid_output_statement()(
            seed_phrase_randomness_1 in any::<[u8; 32]>(),
            seed_phrase_randomness_2 in any::<[u8; 32]>(),
            rseed_randomness in any::<[u8; 32]>(),
            amount in any::<u64>(),
            asset_id64 in any::<u64>(),
            address_index_1 in any::<u32>(),
            address_index_2 in any::<u32>()
        ) -> (OutputProofPublic, OutputProofPrivate) {
            let sk_debtor = sk_from_seed(&seed_phrase_randomness_1);
            let debtor_addr = addr_from_sk(&sk_debtor, address_index_1);
            let spend_auth_randomizer = Fr::from(1u64);
            let rk_debtor = sk_debtor.spend_auth_key().randomize(&spend_auth_randomizer).into();
            let ak = sk_debtor.spend_auth_key().into();
            let nk = *sk_debtor.nullifier_key();

            let sk_creditor = sk_from_seed(&seed_phrase_randomness_2);
            let creditor_addr = addr_from_sk(&sk_creditor, address_index_2);

            let value_to_send = Value {
                amount: Amount::from(amount),
                asset_id: asset::Id(Fq::from(asset_id64)),
            };
            let note = Note::from_parts(
                debtor_addr,
                creditor_addr.clone(),
                value_to_send,
                Rseed(rseed_randomness),
            ).expect("should be able to create note");
            let note_commitment = note.commit();

            // Derive ephemeral secret key.
            let e_sk = note.rseed().derive_esk();

            // Encrypt the output note.
            let c_pk = creditor_addr.transmission_key();
            let d_c_ss = e_sk.key_agreement_with(c_pk).unwrap();
            let d_c_ss_enc = Encoding(d_c_ss.0)
                .vartime_decompress().unwrap();
            let note_ciphertext = ecies_encrypt(d_c_ss_enc, note.to_field_elements().unwrap()).unwrap();
            let e_pk = e_sk.diversified_public(creditor_addr.diversified_generator());

            let public = OutputProofPublic { note_commitment, rk: rk_debtor, note_ciphertext, e_pk };
            let private = OutputProofPrivate { note, spend_auth_randomizer, ak, nk, e_sk };

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
        fn arb_invalid_output_note_commitment_integrity()(
            seed_phrase_randomness_1 in any::<[u8; 32]>(),
            seed_phrase_randomness_2 in any::<[u8; 32]>(),
            rseed_randomness in any::<[u8; 32]>(),
            amount in any::<u64>(),
            asset_id64 in any::<u64>(),
            address_index_1 in any::<u32>(),
            address_index_2 in any::<u32>(),
            incorrect_note_blinding in fq_strategy()
        ) -> (OutputProofPublic, OutputProofPrivate) {
            let sk_debtor = sk_from_seed(&seed_phrase_randomness_1);
            let debtor_addr = addr_from_sk(&sk_debtor, address_index_1);
            let spend_auth_randomizer = Fr::from(1u64);
            let rk = sk_debtor.spend_auth_key().randomize(&spend_auth_randomizer).into();
            let ak = sk_debtor.spend_auth_key().into();
            let nk = *sk_debtor.nullifier_key();

            let sk_creditor = sk_from_seed(&seed_phrase_randomness_2);
            let creditor_addr = addr_from_sk(&sk_creditor, address_index_2);

            let value_to_send = Value {
                amount: Amount::from(amount),
                asset_id: asset::Id(Fq::from(asset_id64)),
            };
            let note = Note::from_parts(
                debtor_addr,
                creditor_addr.clone(),
                value_to_send,
                Rseed(rseed_randomness),
            ).expect("should be able to create note");

            let incorrect_note_commitment = commitment(
                incorrect_note_blinding,
                value_to_send,
                note.diversified_generator(),
                note.transmission_key_s(),
                note.clue_key(),
                *note.creditor().transmission_key_s()
            );

            // Derive ephemeral secret key.
            let e_sk = note.rseed().derive_esk();

            // Encrypt the output note.
            let c_pk = creditor_addr.transmission_key();
            let d_c_ss = e_sk.key_agreement_with(c_pk).unwrap();
            let d_c_ss_enc = Encoding(d_c_ss.0)
                .vartime_decompress().unwrap();
            let note_ciphertext = ecies_encrypt(d_c_ss_enc, note.to_field_elements().unwrap()).unwrap();
            let e_pk = e_sk.diversified_public(creditor_addr.diversified_generator());


            let bad_public = OutputProofPublic { note_commitment: incorrect_note_commitment, rk, note_ciphertext, e_pk };
            let private = OutputProofPrivate { note, spend_auth_randomizer, ak, nk, e_sk };

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
