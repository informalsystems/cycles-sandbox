use decaf377::{Encoding, Fq};
use decaf377_ka::{Error, Public, Secret};
use once_cell::sync::Lazy;
use poseidon377::hash_2;

pub(crate) static ENC_DOMAIN_SEP: Lazy<Fq> =
    Lazy::new(|| Fq::from_le_bytes_mod_order(b"CyclesEncryption"));

pub fn ecies_encrypt(pk: Public, r: &Secret, msg: Vec<Fq>) -> Result<(Public, Vec<Fq>), Error> {
    // compute s = r * pk
    let s = Encoding(r.key_agreement_with(&pk)?.0)
        .vartime_decompress()
        .map_err(|_| Error::InvalidPublic(pk))?;

    // compute c1 = r * generator
    let c1 = r.public();

    let mut c2 = vec![];
    for (i, fq) in msg.into_iter().enumerate() {
        let h = hash_2(
            &ENC_DOMAIN_SEP,
            (s.vartime_compress_to_field(), Fq::from(i as u128)),
        );

        // compute c2 = m + s
        c2.push(fq + h);
    }

    Ok((c1, c2))
}

pub fn ecies_decrypt(sk: &Secret, (c1, c2): (Public, Vec<Fq>)) -> Result<Vec<Fq>, Error> {
    // compute s = sk * c1
    let s = Encoding(sk.key_agreement_with(&c1)?.0)
        .vartime_decompress()
        .map_err(|_| Error::InvalidPublic(c1))?;

    let mut msg = vec![];
    for (i, fq) in c2.into_iter().enumerate() {
        let h = hash_2(
            &ENC_DOMAIN_SEP,
            (s.vartime_compress_to_field(), Fq::from(i as u128)),
        );

        // compute message = c2 - s
        msg.push(fq - h);
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
        let r = Secret::new(&mut rng);
        let receiver_sk = Secret::new(&mut rng);

        let msg: Vec<_> = [0..32].into_iter().map(|_| Fq::rand(&mut rng)).collect();
        let (g_r, ciphertext) = ecies_encrypt(receiver_sk.public(), &r, msg.clone()).unwrap();
        let msg_dec = ecies_decrypt(&receiver_sk, (g_r, ciphertext)).unwrap();
        assert_eq!(msg, msg_dec);
    }
}

pub mod r1cs {}
