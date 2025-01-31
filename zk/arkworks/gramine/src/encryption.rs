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

pub fn ecies_encrypt(s: SharedSecret, msg: Plaintext) -> Result<Ciphertext, Error> {
    // compute c2 = m + s
    let mut c2 = vec![];
    for (i, fq) in msg.into_iter().enumerate() {
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
    let mut msg = vec![];
    for (i, fq) in c2.into_iter().enumerate() {
        let h = hash_2(
            &ENC_DOMAIN_SEP,
            (s.vartime_compress_to_field(), Fq::from(i as u128)),
        );

        msg.push(fq - h);
    }

    Ok(msg)
}

#[cfg(test)]
mod tests {
    use decaf377::{Element, Encoding, Fq};
    use decaf377_ka::{Secret, SharedSecret};
    use rand_core::OsRng;

    use crate::encryption::{ecies_decrypt, ecies_encrypt};

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
}
