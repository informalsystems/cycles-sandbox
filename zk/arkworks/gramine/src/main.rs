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

pub mod note;
pub mod nullifier;
pub mod output;
pub mod proof_bundle;
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
