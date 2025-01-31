use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::borrow::Borrow;
use ark_std::vec::Vec;
use decaf377::r1cs::{ElementVar, FqVar};
use decaf377::Fq;

use crate::encryption::{Ciphertext, Plaintext, SharedSecret, ENC_DOMAIN_SEP};

#[derive(Clone, Debug)]
pub struct PlaintextVar(pub Vec<FqVar>);

impl AllocVar<Plaintext, Fq> for PlaintextVar {
    fn new_variable<T: Borrow<Plaintext>>(
        cs: impl Into<Namespace<Fq>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let plaintext = Vec::<FqVar>::new_variable(cs, || Ok(f()?.borrow().clone()), mode)?;
        Ok(Self(plaintext))
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

fn ecies_encrypt(
    public_key: &SharedSecretVar,
    message: &PlaintextVar,
) -> Result<CiphertextVar, SynthesisError> {
    // compute c2 = m + s
    let mut c2 = vec![];
    let cs = public_key.0.cs();

    let domain_sep = FqVar::new_constant(cs.clone(), *ENC_DOMAIN_SEP)?;
    for (i, fq) in message.0.iter().enumerate() {
        let h = poseidon377::r1cs::hash_2(
            cs.clone(),
            &domain_sep,
            (
                public_key.0.clone().compress_to_field()?,
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
    fn test_ecies_gadget() {
        let rng = &mut OsRng;

        // compute primitive result
        let rseed_1 = Rseed::generate(&mut OsRng);
        let esk_1 = rseed_1.derive_esk();
        let addr_1 = test_keys::ADDRESS_1.clone();
        let pkd_1 = addr_1.transmission_key();
        let shared_secret_1 = esk_1.key_agreement_with(pkd_1).unwrap();
        let ss_as_elm_1 = Encoding(shared_secret_1.0).vartime_decompress().unwrap();
        let msg: Vec<_> = [0..32].into_iter().map(|_| Fq::rand(rng)).collect();
        let primitive_result = ecies_encrypt(ss_as_elm_1, msg.clone()).unwrap();

        // construct constraint system
        let cs = ConstraintSystem::<Fq>::new_ref();
        let msg_var =
            PlaintextVar::new_witness(ark_relations::ns!(cs, "gadget_message"), || Ok(&msg))
                .unwrap();
        let pk_var =
            SharedSecretVar::new_witness(ark_relations::ns!(cs, "gadget_public_key"), || {
                Ok(&ss_as_elm_1)
            })
            .unwrap();

        // use gadget
        let result_var = super::ecies_encrypt(&pk_var, &msg_var).unwrap();

        // check that result equals expected ciphertext in the constraint system
        let expected_var =
            CiphertextVar::new_input(ark_relations::ns!(cs, "gadget_expected"), || {
                Ok(&primitive_result)
            })
            .unwrap();
        expected_var.enforce_equal(&result_var).unwrap();

        assert_eq!(primitive_result, result_var.0.value().unwrap());
        assert!(cs.is_satisfied().unwrap());
    }
}
