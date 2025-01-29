use decaf377::{Encoding, Fq};
use decaf377_ka::{Error, Public, Secret};
use once_cell::sync::Lazy;
use poseidon377::hash_2;

pub(crate) static ENC_DOMAIN_SEP: Lazy<Fq> =
    Lazy::new(|| Fq::from_le_bytes_mod_order(b"CyclesEncryption"));

pub fn ecies_encrypt(
    sender_sk: &Secret,
    receiver_pk: Public,
    msg: Vec<Fq>,
) -> Result<Vec<Fq>, Error> {
    let shared_secret = Encoding(sender_sk.key_agreement_with(&receiver_pk)?.0)
        .vartime_decompress()
        .map_err(|_| Error::InvalidPublic(receiver_pk))?;

    let mut ciphertext = vec![];
    for (i, fq) in msg.into_iter().enumerate() {
        let hash_key = hash_2(
            &ENC_DOMAIN_SEP,
            (
                shared_secret.vartime_compress_to_field(),
                Fq::from(i as u128),
            ),
        );
        ciphertext.push(fq + hash_key);
    }

    Ok(ciphertext)
}

pub fn ecies_decrypt(
    receiver_sk: &Secret,
    sender_pk: Public,
    ciphertext: Vec<Fq>,
) -> Result<Vec<Fq>, Error> {
    let shared_secret = Encoding(receiver_sk.key_agreement_with(&sender_pk)?.0)
        .vartime_decompress()
        .map_err(|_| Error::InvalidPublic(sender_pk))?;

    let mut msg = vec![];
    for (i, fq) in ciphertext.into_iter().enumerate() {
        let hash_key = hash_2(
            &ENC_DOMAIN_SEP,
            (
                shared_secret.vartime_compress_to_field(),
                Fq::from(i as u128),
            ),
        );
        msg.push(fq - hash_key);
    }

    Ok(msg)
}

#[cfg(test)]
mod tests {
    use decaf377::Fq;
    use decaf377_ka::Secret;
    use rand_core::OsRng;

    use crate::encryption::{ecies_decrypt, ecies_encrypt};

    #[test]
    fn test_encryption_roundtrip() {
        let mut rng = OsRng;
        let sender_sk = Secret::new(&mut rng);
        let receiver_sk = Secret::new(&mut rng);

        let msg: Vec<_> = [0..32].into_iter().map(|_| Fq::rand(&mut rng)).collect();
        let ciphertext = ecies_encrypt(&sender_sk, receiver_sk.public(), msg.clone()).unwrap();
        let msg_dec = ecies_decrypt(&receiver_sk, sender_sk.public(), ciphertext).unwrap();
        assert_eq!(msg, msg_dec);
    }
}
