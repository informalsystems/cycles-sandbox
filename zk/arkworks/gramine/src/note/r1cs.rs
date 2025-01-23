use ark_ff::ToConstraintField;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::SynthesisError;
use decaf377::{
    r1cs::{ElementVar, FqVar},
    Fq,
};
use penumbra_asset::ValueVar;
use penumbra_keys::address::AddressVar;
use penumbra_tct::r1cs::StateCommitmentVar;

use super::NOTECOMMIT_DOMAIN_SEP;
use crate::note::Note;

pub struct NoteVar {
    pub value: ValueVar,
    pub note_blinding: FqVar,
    pub debtor: AddressVar,
    pub creditor: AddressVar,
}

impl NoteVar {
    pub fn amount(&self) -> FqVar {
        self.value.amount()
    }

    pub fn value(&self) -> ValueVar {
        self.value.clone()
    }

    #[allow(dead_code)]
    pub fn asset_id(&self) -> FqVar {
        self.value.asset_id()
    }

    #[allow(dead_code)]
    pub fn note_blinding(&self) -> FqVar {
        self.note_blinding.clone()
    }

    pub fn diversified_generator(&self) -> ElementVar {
        self.debtor.diversified_generator.clone()
    }

    pub fn transmission_key(&self) -> ElementVar {
        self.debtor.transmission_key.clone()
    }

    #[allow(dead_code)]
    pub fn clue_key(&self) -> FqVar {
        self.debtor.clue_key.clone()
    }
}

impl AllocVar<Note, Fq> for NoteVar {
    fn new_variable<T: std::borrow::Borrow<Note>>(
        cs: impl Into<ark_relations::r1cs::Namespace<Fq>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        // TODO: figure out how to use namespaces
        let ns = cs.into();
        let cs = ns.cs();
        let note1 = f()?;
        let note: &Note = note1.borrow();
        let note_blinding = FqVar::new_variable(cs.clone(), || Ok(note.note_blinding()), mode)?;
        let value = ValueVar::new_variable(cs.clone(), || Ok(note.value()), mode)?;
        let debtor = AddressVar::new_variable(cs.clone(), || Ok(note.debtor()), mode)?;
        let creditor = AddressVar::new_variable(cs, || Ok(note.creditor()), mode)?;

        let debtor_creditor_eq = {
            let is_eq_d = debtor
                .diversified_generator
                .is_eq(&creditor.diversified_generator)?;
            let is_eq_t = debtor.transmission_key.is_eq(&creditor.transmission_key)?;
            let is_eq_c = debtor.clue_key.is_eq(&creditor.clue_key)?;
            is_eq_d.and(&is_eq_t.and(&is_eq_c)?)?
        };
        debtor_creditor_eq.not().enforce_equal(&Boolean::TRUE)?;

        Ok(Self {
            note_blinding,
            value,
            debtor,
            creditor,
        })
    }
}

impl ToConstraintField<Fq> for Note {
    fn to_field_elements(&self) -> Option<Vec<Fq>> {
        let mut elements = Vec::new();
        let note_blinding = self.note_blinding();
        elements.extend([note_blinding]);
        elements.extend(self.value().to_field_elements()?);
        elements.extend(self.debtor().to_field_elements()?);
        elements.extend(self.creditor().to_field_elements()?);
        Some(elements)
    }
}

// We do not implement `R1CSVar` for `NoteVar` since the associated type
// should be `Note` which we cannot construct from the R1CS variable
// since we do not have the rseed in-circuit.

impl NoteVar {
    pub fn commit(&self) -> Result<StateCommitmentVar, SynthesisError> {
        let cs = self.amount().cs();
        let domain_sep = FqVar::new_constant(cs.clone(), *NOTECOMMIT_DOMAIN_SEP)?;
        let compressed_g_d = self.debtor.diversified_generator().compress_to_field()?;

        let commitment = poseidon377::r1cs::hash_7(
            cs,
            &domain_sep,
            (
                self.note_blinding.clone(),
                self.value.amount(),
                self.value.asset_id(),
                compressed_g_d,
                self.debtor.transmission_key().compress_to_field()?,
                self.debtor.clue_key(),
                self.creditor.transmission_key().compress_to_field()?,
            ),
        )?;

        Ok(StateCommitmentVar { inner: commitment })
    }
}

pub fn enforce_equal_addresses(
    addr1: &AddressVar,
    addr2: &AddressVar,
) -> anyhow::Result<(), SynthesisError> {
    let AddressVar {
        diversified_generator,
        transmission_key,
        clue_key,
    } = addr1;
    addr2
        .diversified_generator
        .enforce_equal(diversified_generator)?;
    addr2.transmission_key.enforce_equal(transmission_key)?;
    addr2.clue_key.enforce_equal(clue_key)?;
    Ok(())
}
