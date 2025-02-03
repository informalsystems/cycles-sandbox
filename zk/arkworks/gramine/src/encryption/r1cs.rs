use crate::encryption::{Ciphertext, Plaintext, SharedSecret, ENC_DOMAIN_SEP};
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::borrow::Borrow;
use ark_std::vec::Vec;
use decaf377::r1cs::{ElementVar, FqVar};
use decaf377::{Encoding, Fq};
use decaf377_ka::Public;

#[derive(Clone, Debug)]
pub struct PlaintextVar(pub Vec<FqVar>);

impl AllocVar<Plaintext, Fq> for PlaintextVar {
    fn new_variable<T: Borrow<Plaintext>>(
        cs: impl Into<Namespace<Fq>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let plaintext = Vec::<FqVar>::new_variable(cs, || Ok(f()?.borrow().clone()), mode)?;
        Ok(Self(plaintext))
    }
}

impl EqGadget<Fq> for PlaintextVar {
    #[inline]
    fn is_eq(&self, other: &Self) -> Result<Boolean<Fq>, SynthesisError> {
        Ok(self.0.is_eq(&other.0)?)
    }
}

#[derive(Clone, Debug)]
pub struct SharedSecretVar(pub ElementVar);

impl AllocVar<SharedSecret, Fq> for SharedSecretVar {
    fn new_variable<T: Borrow<SharedSecret>>(
        cs: impl Into<Namespace<Fq>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let pk = ElementVar::new_variable(cs, || Ok(*f()?.borrow()), mode)?;
        Ok(Self(pk))
    }
}

#[derive(Clone, Debug)]
pub struct CiphertextVar(pub Vec<FqVar>);

impl AllocVar<Ciphertext, Fq> for CiphertextVar {
    fn new_variable<T: Borrow<Ciphertext>>(
        cs: impl Into<Namespace<Fq>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let prep = f().map(|g| g.borrow().clone());
        let c2 = Vec::<FqVar>::new_variable(cs.clone(), || prep, mode)?;
        Ok(Self(c2))
    }
}

impl EqGadget<Fq> for CiphertextVar {
    #[inline]
    fn is_eq(&self, other: &Self) -> Result<Boolean<Fq>, SynthesisError> {
        Ok(self.0.is_eq(&other.0)?)
    }
}

#[derive(Clone, Debug)]
pub struct PublicKeyVar(pub ElementVar);

impl AllocVar<Public, Fq> for PublicKeyVar {
    fn new_variable<T: Borrow<Public>>(
        cs: impl Into<Namespace<Fq>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let pk = {
            let pk = *f()?.borrow();
            Encoding(pk.0)
                .vartime_decompress()
                .map_err(|_| SynthesisError::UnexpectedIdentity)?
        };
        let pk_var = ElementVar::new_variable(cs, || Ok(pk), mode)?;
        Ok(Self(pk_var))
    }
}

pub fn ecies_encrypt(
    s: &SharedSecretVar,
    m: &PlaintextVar,
) -> Result<CiphertextVar, SynthesisError> {
    // compute c2 = m + s
    let mut c2 = vec![];
    let cs = s.0.cs();

    let domain_sep = FqVar::new_constant(cs.clone(), *ENC_DOMAIN_SEP)?;
    for (i, fq) in m.0.iter().enumerate() {
        let h = poseidon377::r1cs::hash_2(
            cs.clone(),
            &domain_sep,
            (
                s.0.clone().compress_to_field()?,
                FqVar::new_constant(cs.clone(), Fq::from(i as u128))?,
            ),
        )?;
        c2.push(fq + h);
    }

    Ok(CiphertextVar(c2))
}

pub fn ecies_decrypt(
    s: &SharedSecretVar,
    c2: &CiphertextVar,
) -> Result<PlaintextVar, SynthesisError> {
    // compute c2 = m + s
    let mut m = vec![];
    let cs = s.0.cs();

    let domain_sep = FqVar::new_constant(cs.clone(), *ENC_DOMAIN_SEP)?;
    for (i, fq) in c2.0.iter().enumerate() {
        let h = poseidon377::r1cs::hash_2(
            cs.clone(),
            &domain_sep,
            (
                s.0.clone().compress_to_field()?,
                FqVar::new_constant(cs.clone(), Fq::from(i as u128))?,
            ),
        )?;
        m.push(fq - h);
    }

    Ok(PlaintextVar(m))
}

#[cfg(test)]
mod test {
    use ark_r1cs_std::prelude::*;
    use ark_relations::r1cs::ConstraintSystem;
    use decaf377::{Encoding, Fq};
    use penumbra_keys::test_keys;
    use penumbra_shielded_pool::Rseed;
    use rand_core::OsRng;

    use crate::encryption::ecies_encrypt;
    use crate::encryption::r1cs::{CiphertextVar, PlaintextVar, SharedSecretVar};

    #[test]
    fn test_ecies_encrypt() {
        let rng = &mut OsRng;

        // compute primitive result
        let s = {
            let rseed = Rseed::generate(&mut OsRng);
            let esk = rseed.derive_esk();
            let addr = test_keys::ADDRESS_1.clone();
            let pkd = addr.transmission_key();
            esk.key_agreement_with(pkd).unwrap()
        };
        let s_element = Encoding(s.0).vartime_decompress().unwrap();
        let m: Vec<_> = [0..32].into_iter().map(|_| Fq::rand(rng)).collect();
        let c2 = ecies_encrypt(s_element, m.clone()).unwrap();

        // construct constraint system
        let cs = ConstraintSystem::<Fq>::new_ref();
        let m_var =
            PlaintextVar::new_witness(ark_relations::ns!(cs, "gadget_m"), || Ok(&m)).unwrap();
        let s_var =
            SharedSecretVar::new_witness(ark_relations::ns!(cs, "gadget_s"), || Ok(&s_element))
                .unwrap();

        // use gadget
        let c2_var = super::ecies_encrypt(&s_var, &m_var).unwrap();

        // check that result equals expected ciphertext in the constraint system
        let expected_c2_var =
            CiphertextVar::new_input(ark_relations::ns!(cs, "gadget_expected_c2"), || Ok(&c2))
                .unwrap();
        expected_c2_var.enforce_equal(&c2_var).unwrap();

        assert_eq!(c2, c2_var.0.value().unwrap());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_ecies_decrypt() {
        let rng = &mut OsRng;

        // compute primitive result
        let s = {
            let rseed = Rseed::generate(&mut OsRng);
            let esk = rseed.derive_esk();
            let addr = test_keys::ADDRESS_1.clone();
            let pkd = addr.transmission_key();
            esk.key_agreement_with(pkd).unwrap()
        };
        let s_element = Encoding(s.0).vartime_decompress().unwrap();
        let m: Vec<_> = [0..32].into_iter().map(|_| Fq::rand(rng)).collect();
        let c2 = ecies_encrypt(s_element, m.clone()).unwrap();

        // construct constraint system
        let cs = ConstraintSystem::<Fq>::new_ref();
        let c2_var =
            CiphertextVar::new_input(ark_relations::ns!(cs, "gadget_c2"), || Ok(&c2)).unwrap();
        let s_var =
            SharedSecretVar::new_witness(ark_relations::ns!(cs, "gadget_s"), || Ok(&s_element))
                .unwrap();

        // use gadget
        let m_var = super::ecies_decrypt(&s_var, &c2_var).unwrap();

        // check that result equals expected ciphertext in the constraint system
        let expected_m_var =
            PlaintextVar::new_input(ark_relations::ns!(cs, "gadget_expected_m"), || Ok(&m))
                .unwrap();
        expected_m_var.enforce_equal(&m_var).unwrap();

        assert_eq!(m, m_var.0.value().unwrap());
        assert!(cs.is_satisfied().unwrap());
    }
}
