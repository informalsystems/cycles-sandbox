use ark_groth16::ProvingKey;
use ark_serialize::CanonicalDeserialize;
use decaf377::{Fq, Fr};
use penumbra_asset::{asset, Balance, Value};
use penumbra_keys::keys::{Bip44Path, SeedPhrase, SpendKey};
use penumbra_shielded_pool::{
    output::{OutputProofPrivate, OutputProofPublic},
    Note, OutputProof,
};
use rand_core::OsRng;

const OUTPUT_PROOF_PROVING_KEY: &[u8] = include_bytes!("../data/output_pk.bin");

mod proof_bundle {
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
}

pub mod output;
pub mod settlement;

fn main() {
    let pk = ProvingKey::deserialize_uncompressed_unchecked(OUTPUT_PROOF_PROVING_KEY)
        .expect("can serialize");

    let (public, private) = {
        let mut rng = OsRng;

        let seed_phrase = SeedPhrase::generate(OsRng);
        let sk_recipient = SpendKey::from_seed_phrase_bip44(seed_phrase, &Bip44Path::new(0));
        let fvk_recipient = sk_recipient.full_viewing_key();
        let ivk_recipient = fvk_recipient.incoming();
        let (dest, _dtk_d) = ivk_recipient.payment_address(0u32.into());

        let value_to_send = Value {
            amount: 1u64.into(),
            asset_id: asset::Cache::with_known_assets()
                .get_unit("upenumbra")
                .unwrap()
                .id(),
        };
        let balance_blinding = Fr::rand(&mut OsRng);

        let note = Note::generate(&mut rng, &dest, value_to_send);
        let note_commitment = note.commit();
        let balance_commitment = (-Balance::from(value_to_send)).commit(balance_blinding);

        let public = OutputProofPublic {
            balance_commitment,
            note_commitment,
        };
        let private = OutputProofPrivate {
            note,
            balance_blinding,
        };

        (public, private)
    };

    let blinding_r = Fq::rand(&mut OsRng);
    let blinding_s = Fq::rand(&mut OsRng);
    let proof = OutputProof::prove(blinding_r, blinding_s, &pk, public.clone(), private)
        .expect("can create proof");

    let proof_bundle = proof_bundle::Groth16ProofBundle::new_from_output_proof(proof, public)
        .expect("public inputs cannot be converted to valid field elements");
    println!(
        "proof: {}",
        hex::encode(to_canonical_bytes(proof_bundle.proof))
    );
    println!(
        "public_inputs: {}",
        hex::encode(to_canonical_bytes(proof_bundle.public_inputs))
    );
}

fn to_canonical_bytes(t: impl ark_serialize::CanonicalSerialize) -> Vec<u8> {
    let mut out = Vec::new();
    t.serialize_compressed(&mut out).expect("can serialize");
    out
}
