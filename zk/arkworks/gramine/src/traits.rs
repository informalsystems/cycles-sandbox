use ark_ec::pairing::Pairing;
use ark_groth16::{
    r1cs_to_qap::LibsnarkReduction, Groth16, PreparedVerifyingKey, ProvingKey, VerifyingKey,
};
use ark_serialize::CanonicalSerialize;
use decaf377::Bls12_377;

// We only need this import from the traits module for now, so the others are removed as 
// to not have to figure out the dependency errors they raise

pub trait ProvingKeyExt {
    fn debug_id(&self) -> String;
}

impl ProvingKeyExt for ProvingKey<Bls12_377> {
    fn debug_id(&self) -> String {
        let mut buf = Vec::new();
        self.serialize_compressed(&mut buf)
            .expect("can serialize pk");
        use sha2::Digest;
        let hash = sha2::Sha256::digest(&buf);
        use bech32::ToBase32;
        bech32::encode("groth16pk", hash.to_base32(), bech32::Variant::Bech32m)
            .expect("can encode pk as bech32")
    }
}