use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::SynthesisError;
use decaf377::{r1cs::FqVar, Fq};
use once_cell::sync::Lazy;
use penumbra_proto::{core::component::sct::v1 as pb, DomainType};
use poseidon377::hash_6;
use serde::{Deserialize, Serialize};

use crate::note::{r1cs::NoteVar, Note};

#[derive(PartialEq, Eq, Clone, Copy, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "pb::Nullifier", into = "pb::Nullifier")]
pub struct Nullifier(pub Fq);

impl Nullifier {
    pub fn parse_hex(str: &str) -> anyhow::Result<Nullifier> {
        let bytes = hex::decode(str)?;
        Nullifier::try_from(&bytes[..])
    }
}

impl DomainType for Nullifier {
    type Proto = pb::Nullifier;
}

impl From<Nullifier> for pb::Nullifier {
    fn from(n: Nullifier) -> Self {
        pb::Nullifier {
            inner: n.0.to_bytes().to_vec(),
        }
    }
}

impl TryFrom<pb::Nullifier> for Nullifier {
    type Error = anyhow::Error;
    fn try_from(n: pb::Nullifier) -> Result<Self, Self::Error> {
        n.inner.as_slice().try_into()
    }
}

/// The domain separator used to derive nullifiers.
pub static NULLIFIER_DOMAIN_SEP: Lazy<Fq> = Lazy::new(|| {
    Fq::from_le_bytes_mod_order(blake2b_simd::blake2b(b"penumbra.nullifier").as_bytes())
});

impl std::fmt::Display for Nullifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.to_bytes()))
    }
}

impl std::fmt::Debug for Nullifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Nullifier")
            .field(&hex::encode(self.to_bytes()))
            .finish()
    }
}

impl Nullifier {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Derive the [`Nullifier`] for a positioned note or swap given its [`merkle::Position`]
    /// and [`Commitment`].
    pub fn derive(note: &Note) -> Nullifier {
        Nullifier(hash_6(
            &NULLIFIER_DOMAIN_SEP,
            (
                note.note_blinding(),
                note.value().amount.into(),
                note.value().asset_id.0,
                note.diversified_generator().vartime_compress_to_field(),
                note.transmission_key_s(),
                Fq::from_le_bytes_mod_order(&note.clue_key().0[..]),
            ),
        ))
    }
}

impl From<Nullifier> for [u8; 32] {
    fn from(nullifier: Nullifier) -> [u8; 32] {
        nullifier.0.to_bytes()
    }
}

impl TryFrom<&[u8]> for Nullifier {
    type Error = anyhow::Error;

    fn try_from(slice: &[u8]) -> Result<Nullifier, Self::Error> {
        let bytes: [u8; 32] = slice[..].try_into()?;
        let inner = Fq::from_bytes_checked(&bytes).expect("convert from bytes");
        Ok(Nullifier(inner))
    }
}

impl TryFrom<Vec<u8>> for Nullifier {
    type Error = anyhow::Error;

    fn try_from(vec: Vec<u8>) -> Result<Nullifier, Self::Error> {
        Self::try_from(&vec[..])
    }
}

pub struct NullifierVar {
    pub inner: FqVar,
}

impl AllocVar<Nullifier, Fq> for NullifierVar {
    fn new_variable<T: std::borrow::Borrow<Nullifier>>(
        cs: impl Into<ark_relations::r1cs::Namespace<Fq>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let inner: Nullifier = *f()?.borrow();
        match mode {
            AllocationMode::Constant => unimplemented!(),
            AllocationMode::Input => Ok(Self {
                inner: FqVar::new_input(cs, || Ok(inner.0))?,
            }),
            AllocationMode::Witness => unimplemented!(),
        }
    }
}

impl R1CSVar<Fq> for NullifierVar {
    type Value = Nullifier;

    fn cs(&self) -> ark_relations::r1cs::ConstraintSystemRef<Fq> {
        self.inner.cs()
    }

    fn value(&self) -> Result<Self::Value, SynthesisError> {
        Ok(Nullifier(self.inner.value()?))
    }
}

impl EqGadget<Fq> for NullifierVar {
    fn is_eq(&self, other: &Self) -> Result<Boolean<Fq>, SynthesisError> {
        self.inner.is_eq(&other.inner)
    }
}

impl NullifierVar {
    pub fn derive(note: &NoteVar) -> Result<NullifierVar, SynthesisError> {
        let cs = note.amount().cs();
        let domain_sep = FqVar::new_constant(cs.clone(), *NULLIFIER_DOMAIN_SEP)?;
        let compressed_g_d = note.debtor.diversified_generator().compress_to_field()?;

        let nullifier = poseidon377::r1cs::hash_6(
            cs,
            &domain_sep,
            (
                note.note_blinding.clone(),
                note.value.amount(),
                note.value.asset_id(),
                compressed_g_d,
                note.debtor.transmission_key().compress_to_field()?,
                note.debtor.clue_key(),
            ),
        )?;

        Ok(NullifierVar { inner: nullifier })
    }
}
