use ark_crypto_primitives::encryption::AsymmetricEncryptionGadget;
use ark_ff::Zero;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_serialize::CanonicalSerialize;
use ark_std::borrow::Borrow;
use ark_std::vec::Vec;
use decaf377::fields::fr::u64::Fr;
use decaf377::r1cs::{ElementVar, FqVar};
use decaf377::{Encoding, Fq};

use crate::encryption::{
    Ciphertext, Ecies, Parameters, Plaintext, PublicKey, Randomness, ENC_DOMAIN_SEP,
};

#[derive(Clone, Debug)]
pub struct RandomnessVar(Vec<UInt8<Fq>>);

impl AllocVar<Randomness, Fq> for RandomnessVar {
    fn new_variable<T: Borrow<Randomness>>(
        cs: impl Into<Namespace<Fq>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let mut r = Vec::new();
        let _ = &f()
            .map(|b| {
                let r = b.borrow();
                Fr::from_bytes_checked(&r.to_bytes()).unwrap()
            })
            .unwrap_or(Fr::zero())
            .serialize_compressed(&mut r)
            .unwrap();
        match mode {
            AllocationMode::Constant => Ok(Self(UInt8::constant_vec(&r))),
            AllocationMode::Input => UInt8::new_input_vec(cs, &r).map(Self),
            AllocationMode::Witness => UInt8::new_witness_vec(cs, &r).map(Self),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ParametersVar {
    generator: ElementVar,
}

impl AllocVar<Parameters, Fq> for ParametersVar {
    fn new_variable<T: Borrow<Parameters>>(
        cs: impl Into<Namespace<Fq>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let generator = ElementVar::new_variable(cs, || f().map(|g| g.borrow().generator), mode)?;
        Ok(Self { generator })
    }
}

#[derive(Clone, Debug)]
pub struct PlaintextVar(Vec<FqVar>);

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
pub struct PublicKeyVar(ElementVar);

impl AllocVar<PublicKey, Fq> for PublicKeyVar {
    fn new_variable<T: Borrow<PublicKey>>(
        cs: impl Into<Namespace<Fq>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let element = Encoding(f()?.borrow().0)
            .vartime_decompress()
            .map_err(|_| SynthesisError::AssignmentMissing)?;
        let pk = ElementVar::new_variable(cs, || Ok(element), mode)?;
        Ok(Self(pk))
    }
}

#[derive(Clone, Debug)]
pub struct CiphertextVar(PublicKeyVar, Vec<FqVar>);

impl AllocVar<Ciphertext, Fq> for CiphertextVar {
    fn new_variable<T: Borrow<Ciphertext>>(
        cs: impl Into<Namespace<Fq>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let prep = f().map(|g| g.borrow().clone());
        let c1 = PublicKeyVar::new_variable(cs.clone(), || prep.clone().map(|g| g.0), mode)?;
        let c2 = Vec::<FqVar>::new_variable(cs.clone(), || prep.map(|g| g.1), mode)?;
        Ok(Self(c1, c2))
    }
}

impl EqGadget<Fq> for CiphertextVar {
    #[inline]
    fn is_eq(&self, other: &Self) -> Result<Boolean<Fq>, SynthesisError> {
        Ok(self
            .0
             .0
            .is_eq(&other.0 .0)?
            .and(&self.1.is_eq(&other.1)?)?)
    }
}

pub struct EciesEncGadget;

impl AsymmetricEncryptionGadget<Ecies, Fq> for EciesEncGadget {
    type OutputVar = CiphertextVar;
    type ParametersVar = ParametersVar;
    type PlaintextVar = PlaintextVar;
    type PublicKeyVar = PublicKeyVar;
    type RandomnessVar = RandomnessVar;

    fn encrypt(
        parameters: &Self::ParametersVar,
        message: &Self::PlaintextVar,
        randomness: &Self::RandomnessVar,
        public_key: &Self::PublicKeyVar,
    ) -> Result<Self::OutputVar, SynthesisError> {
        // flatten randomness to little-endian bit vector
        let randomness = randomness
            .0
            .iter()
            .flat_map(|b| b.to_bits_le().unwrap())
            .collect::<Vec<_>>();

        // compute s = r * pk
        let s = public_key.0.clone().scalar_mul_le(randomness.iter())?;

        // compute c1 = r * g
        let c1 = parameters
            .generator
            .clone()
            .scalar_mul_le(randomness.iter())?;

        // compute c2 = m + s
        let mut c2 = vec![];
        let cs = c1.cs();
        let domain_sep = FqVar::new_constant(cs.clone(), *ENC_DOMAIN_SEP)?;
        for (i, fq) in message.0.iter().enumerate() {
            let h = poseidon377::r1cs::hash_2(
                cs.clone(),
                &domain_sep,
                (
                    s.clone().compress_to_field()?,
                    FqVar::new_constant(cs.clone(), Fq::from(i as u128))?,
                ),
            )?;

            // compute c2 = m + s
            c2.push(fq + h);
        }

        Ok(CiphertextVar(PublicKeyVar(c1), c2))
    }
}

#[cfg(test)]
mod test {
    use ark_crypto_primitives::encryption::{
        AsymmetricEncryptionGadget, AsymmetricEncryptionScheme,
    };
    use ark_r1cs_std::prelude::*;
    use ark_relations::r1cs::ConstraintSystem;
    use decaf377::{Encoding, Fq};
    use rand_core::OsRng;

    use crate::encryption::{r1cs::EciesEncGadget, Ecies, Randomness};

    #[test]
    fn test_elgamal_gadget() {
        let rng = &mut OsRng;

        type MyEnc = Ecies;
        type MyGadget = EciesEncGadget;

        // compute primitive result
        let parameters = MyEnc::setup(rng).unwrap();
        let (pk, _) = MyEnc::keygen(&parameters, rng).unwrap();
        let msg: Vec<_> = [0..32].into_iter().map(|_| Fq::rand(rng)).collect();
        let randomness = Randomness::new(rng);
        let primitive_result = MyEnc::encrypt(&parameters, &pk, &msg, &randomness).unwrap();

        // construct constraint system
        let cs = ConstraintSystem::<Fq>::new_ref();
        let randomness_var =
            <MyGadget as AsymmetricEncryptionGadget<MyEnc, Fq>>::RandomnessVar::new_witness(
                ark_relations::ns!(cs, "gadget_randomness"),
                || Ok(&randomness),
            )
            .unwrap();
        let parameters_var =
            <MyGadget as AsymmetricEncryptionGadget<MyEnc, Fq>>::ParametersVar::new_constant(
                ark_relations::ns!(cs, "gadget_parameters"),
                &parameters,
            )
            .unwrap();
        let msg_var =
            <MyGadget as AsymmetricEncryptionGadget<MyEnc, Fq>>::PlaintextVar::new_witness(
                ark_relations::ns!(cs, "gadget_message"),
                || Ok(&msg),
            )
            .unwrap();
        let pk_var =
            <MyGadget as AsymmetricEncryptionGadget<MyEnc, Fq>>::PublicKeyVar::new_witness(
                ark_relations::ns!(cs, "gadget_public_key"),
                || Ok(&pk),
            )
            .unwrap();

        // use gadget
        let result_var =
            MyGadget::encrypt(&parameters_var, &msg_var, &randomness_var, &pk_var).unwrap();

        // check that result equals expected ciphertext in the constraint system
        let expected_var =
            <MyGadget as AsymmetricEncryptionGadget<MyEnc, Fq>>::OutputVar::new_input(
                ark_relations::ns!(cs, "gadget_expected"),
                || Ok(&primitive_result),
            )
            .unwrap();
        expected_var.enforce_equal(&result_var).unwrap();

        assert_eq!(
            Encoding(primitive_result.0 .0)
                .vartime_decompress()
                .unwrap(),
            result_var.0 .0.value().unwrap()
        );
        assert_eq!(primitive_result.1, result_var.1.value().unwrap());
        assert!(cs.is_satisfied().unwrap());
    }
}
