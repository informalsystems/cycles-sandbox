use ark_crypto_primitives::encryption::AsymmetricEncryptionScheme;
use ark_crypto_primitives::Error as ArkworksError;
use decaf377::{Element, Encoding, Fq};
use decaf377_ka::{Error, Public, Secret};
use once_cell::sync::Lazy;
use poseidon377::hash_2;
use rand::Rng;
use rand_core::OsRng;

pub(crate) static ENC_DOMAIN_SEP: Lazy<Fq> =
    Lazy::new(|| Fq::from_le_bytes_mod_order(b"CyclesEncryption"));

pub mod r1cs;

pub type PublicKey = Public;
pub type SecretKey = Secret;
pub type Randomness = Secret;
pub type Plaintext = Vec<Fq>;
pub type Ciphertext = (Public, Vec<Fq>);
pub struct Parameters {
    generator: Element,
}

pub struct Ecies;

impl AsymmetricEncryptionScheme for Ecies {
    type Parameters = Parameters;
    type PublicKey = Public;
    type SecretKey = Secret;
    type Randomness = Secret;
    type Plaintext = Vec<Fq>;
    type Ciphertext = (Public, Vec<Fq>);

    fn setup<R: Rng>(_rng: &mut R) -> Result<Self::Parameters, ArkworksError> {
        Ok(Parameters {
            generator: Element::GENERATOR,
        })
    }

    fn keygen<R: Rng>(
        _pp: &Self::Parameters,
        _rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), ArkworksError> {
        let sk = Secret::new(&mut OsRng);
        Ok((sk.public(), sk))
    }

    fn encrypt(
        _pp: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &Self::Plaintext,
        r: &Self::Randomness,
    ) -> Result<Self::Ciphertext, ArkworksError> {
        ecies_encrypt(pk.clone(), r, message.clone()).map_err(Into::into)
    }

    fn decrypt(
        _pp: &Self::Parameters,
        sk: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::Plaintext, ArkworksError> {
        ecies_decrypt(sk, ciphertext.clone()).map_err(Into::into)
    }
}

pub fn ecies_encrypt(pk: Public, r: &Secret, msg: Vec<Fq>) -> Result<(Public, Vec<Fq>), Error> {
    // compute s = r * pk
    let s = Encoding(r.key_agreement_with(&pk)?.0)
        .vartime_decompress()
        .map_err(|_| Error::InvalidPublic(pk))?;

    // compute c1 = r * generator
    let c1 = r.public();

    // compute c2 = m + s
    let mut c2 = vec![];
    for (i, fq) in msg.into_iter().enumerate() {
        let h = hash_2(
            &ENC_DOMAIN_SEP,
            (s.vartime_compress_to_field(), Fq::from(i as u128)),
        );

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
