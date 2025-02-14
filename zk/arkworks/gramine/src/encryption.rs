use decaf377::{Element, Fq};
use decaf377_ka::Error;
use once_cell::sync::Lazy;
use poseidon377::hash_2;

pub(crate) static ENC_DOMAIN_SEP: Lazy<Fq> =
    Lazy::new(|| Fq::from_le_bytes_mod_order(b"CyclesEncryption"));

pub mod r1cs;

pub type SharedSecret = Element;
pub type Plaintext = Vec<Fq>;
pub type Ciphertext = Vec<Fq>;

pub fn ecies_encrypt(s: SharedSecret, m: Plaintext) -> Result<Ciphertext, Error> {
    // compute c2 = m + s
    let mut c2 = vec![];
    for (i, fq) in m.into_iter().enumerate() {
        let h = hash_2(
            &ENC_DOMAIN_SEP,
            (s.vartime_compress_to_field(), Fq::from(i as u128)),
        );

        c2.push(fq + h);
    }

    Ok(c2)
}

pub fn ecies_decrypt(s: SharedSecret, c2: Ciphertext) -> Result<Plaintext, Error> {
    // compute message = c2 - s
    let mut m = vec![];
    for (i, fq) in c2.into_iter().enumerate() {
        let h = hash_2(
            &ENC_DOMAIN_SEP,
            (s.vartime_compress_to_field(), Fq::from(i as u128)),
        );

        m.push(fq - h);
    }

    Ok(m)
}

#[cfg(test)]
mod tests {
    use decaf377::{Element, Encoding, Fq};
    use decaf377_ka::{Secret, SharedSecret};
    use penumbra_asset::{asset::Id, Value};
    use penumbra_keys::Address;
    use penumbra_shielded_pool::Rseed;
    use rand_core::OsRng;

    use crate::{
        canonical::{CanonicalFqDecoding, CanonicalFqEncoding},
        encryption::{ecies_decrypt, ecies_encrypt},
        note::Note,
    };

    fn ss_as_element(ss: SharedSecret) -> Element {
        Encoding(ss.0).vartime_decompress().unwrap()
    }

    #[test]
    fn test_encryption_roundtrip() {
        let mut rng = OsRng;
        let r = Secret::new(&mut rng);
        let receiver_sk = Secret::new(&mut rng);
        let msg: Vec<_> = [0..32].into_iter().map(|_| Fq::rand(&mut rng)).collect();
        let receiver_pk = receiver_sk.public();
        let s = r.key_agreement_with(&receiver_pk).unwrap();
        let ciphertext = ecies_encrypt(ss_as_element(s.clone()), msg.clone()).unwrap();
        let msg_dec = ecies_decrypt(ss_as_element(s), ciphertext).unwrap();
        assert_eq!(msg, msg_dec);
    }

    #[test]
    fn test_note_encryption_roundtrip() {
        let mut rng = OsRng;

        for _ in 0..100 {
            let original = Note::from_parts(
                Address::dummy(&mut rng),
                Address::dummy(&mut rng),
                Value {
                    amount: 10u64.into(),
                    asset_id: Id(Fq::from(1u64)),
                },
                Rseed::generate(&mut rng),
            )
            .expect("hardcoded note");

            let r = Secret::new(&mut rng);
            let receiver_sk = Secret::new(&mut rng);
            let receiver_pk = receiver_sk.public();
            let s = r.key_agreement_with(&receiver_pk).unwrap();

            let msg: Vec<Fq> = original.canonical_encoding();

            let ciphertext = ecies_encrypt(ss_as_element(s.clone()), msg.clone()).unwrap();
            let msg_dec = ecies_decrypt(ss_as_element(s), ciphertext).unwrap();

            let note = Note::canonical_decoding(&msg_dec).unwrap();

            assert_eq!(note, original);
        }
    }
}
