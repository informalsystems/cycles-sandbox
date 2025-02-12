use std::fmt;

use ark_ff::ToConstraintField;
use decaf377::Fq;
use decaf377_fmd as fmd;
use decaf377_ka as ka;
use once_cell::sync::Lazy;
use penumbra_asset::{asset, Value};
use penumbra_keys::keys::{Diversifier, DIVERSIFIER_LEN_BYTES};
use penumbra_keys::Address;
use penumbra_num::Amount;
use penumbra_shielded_pool::note::Error;
use penumbra_shielded_pool::Rseed;
use penumbra_tct::StateCommitment;
use serde::de::{MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

pub mod r1cs;

pub(crate) static NOTECOMMIT_DOMAIN_SEP: Lazy<Fq> = Lazy::new(|| {
    Fq::from_le_bytes_mod_order(blake2b_simd::blake2b(b"penumbra.notecommit").as_bytes())
});

/// A plaintext Penumbra note.
#[derive(Clone, PartialEq, Eq)]
pub struct Note {
    /// The typed value recorded by this note.
    value: Value,
    /// A uniformly random 32-byte sequence used to derive an ephemeral secret key
    /// and note blinding factor.
    rseed: Rseed,
    /// The address controlling this note.
    debtor: Address,
    /// The credit of this note.
    creditor: Address,
    /// The s-component of the transmission key of the destination address.
    /// We store this separately to ensure that every `Note` is constructed
    /// with a valid transmission key (the `ka::Public` does not validate
    /// the curve point until it is used, since validation is not free).
    transmission_key_s: Fq,
    creditor_transmission_key_s: Fq,
}

impl Note {
    pub fn transmission_key(&self) -> &ka::Public {
        self.debtor.transmission_key()
    }
}

impl Note {
    pub fn from_parts(
        debtor: Address,
        creditor: Address,
        value: Value,
        rseed: Rseed,
    ) -> Result<Self, Error> {
        if debtor == creditor {
            return Err(Error::NoteTypeUnsupported);
        }

        Ok(Self {
            value,
            rseed,
            debtor: debtor.clone(),
            creditor: creditor.clone(),
            transmission_key_s: Fq::from_bytes_checked(&debtor.transmission_key().0)
                .map_err(|_| Error::InvalidTransmissionKey)?,
            creditor_transmission_key_s: Fq::from_bytes_checked(&creditor.transmission_key().0)
                .map_err(|_| Error::InvalidTransmissionKey)?,
        })
    }

    pub fn debtor(&self) -> Address {
        self.debtor.clone()
    }

    pub fn creditor(&self) -> Address {
        self.creditor.clone()
    }

    pub fn note_blinding(&self) -> Fq {
        self.rseed.derive_note_blinding()
    }

    pub fn value(&self) -> Value {
        self.value
    }

    pub fn diversified_generator(&self) -> decaf377::Element {
        self.debtor.diversifier().diversified_generator()
    }

    pub fn transmission_key_s(&self) -> Fq {
        self.transmission_key_s
    }

    pub fn clue_key(&self) -> &fmd::ClueKey {
        self.debtor.clue_key()
    }

    pub fn commit(&self) -> StateCommitment {
        self::commitment(
            self.note_blinding(),
            self.value,
            self.diversified_generator(),
            self.transmission_key_s,
            self.debtor.clue_key(),
            self.creditor_transmission_key_s,
        )
    }

    pub fn asset_id(&self) -> asset::Id {
        self.value.asset_id
    }

    pub fn amount(&self) -> Amount {
        self.value.amount
    }

    pub fn rseed(&self) -> Rseed {
        self.rseed
    }
}

impl std::fmt::Debug for Note {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Note")
            .field("value", &self.value)
            .field("debtor", &self.debtor())
            .field("creditor", &self.creditor())
            .field("rseed", &hex::encode(self.rseed.to_bytes()))
            .finish()
    }
}

pub fn commitment(
    note_blinding: Fq,
    value: Value,
    diversified_generator: decaf377::Element,
    transmission_key_s: Fq,
    clue_key: &fmd::ClueKey,
    creditor_transmission_key_s: Fq,
) -> StateCommitment {
    let commit = poseidon377::hash_7(
        &NOTECOMMIT_DOMAIN_SEP,
        (
            note_blinding,
            value.amount.into(),
            value.asset_id.0,
            diversified_generator.vartime_compress_to_field(),
            transmission_key_s,
            Fq::from_le_bytes_mod_order(&clue_key.0[..]),
            creditor_transmission_key_s,
        ),
    );

    StateCommitment(commit)
}

// Implement Serialize for Note
impl Serialize for Note {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Use a map to serialize fields
        let mut state = serializer.serialize_struct("Note", 4)?;
        state.serialize_field("value", &self.value)?;
        state.serialize_field("rseed", &self.rseed.to_bytes())?;
        state.serialize_field("debtor", &self.debtor)?;
        state.serialize_field("creditor", &self.creditor)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Note {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Value,
            Rseed,
            Debtor,
            Creditor,
        }

        struct NoteVisitor;

        impl<'de> Visitor<'de> for NoteVisitor {
            type Value = Note;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct Note")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut value = None;
                let mut rseed = None;
                let mut debtor = None;
                let mut creditor = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Value => {
                            if value.is_some() {
                                return Err(de::Error::duplicate_field("value"));
                            }
                            value = Some(map.next_value()?);
                        }
                        Field::Rseed => {
                            if rseed.is_some() {
                                return Err(de::Error::duplicate_field("rseed"));
                            }
                            rseed = Some(Rseed(map.next_value::<[u8; 32]>()?));
                        }
                        Field::Debtor => {
                            if debtor.is_some() {
                                return Err(de::Error::duplicate_field("debtor"));
                            }
                            debtor = Some(map.next_value()?);
                        }
                        Field::Creditor => {
                            if creditor.is_some() {
                                return Err(de::Error::duplicate_field("creditor"));
                            }
                            creditor = Some(map.next_value()?);
                        }
                    }
                }

                let value = value.ok_or_else(|| de::Error::missing_field("value"))?;
                let rseed = rseed.ok_or_else(|| de::Error::missing_field("rseed"))?;
                let debtor = debtor.ok_or_else(|| de::Error::missing_field("debtor"))?;
                let creditor = creditor.ok_or_else(|| de::Error::missing_field("creditor"))?;

                Note::from_parts(debtor, creditor, value, rseed).map_err(de::Error::custom)
            }
        }

        const FIELDS: &[&str] = &["value", "rseed", "debtor", "creditor"];
        deserializer.deserialize_struct("Note", FIELDS, NoteVisitor)
    }
}


#[cfg(test)]
mod test {
    use crate::{canonical::{CanonicalFqEncoding, CanonicalFqDecoding}, note::Note};
    use decaf377::Fq;
    use penumbra_asset::asset::Id;
    use penumbra_asset::Value;
    use penumbra_keys::Address;
    use penumbra_shielded_pool::Rseed;
    use rand::{thread_rng, Rng, RngCore};

    #[test]
    fn test_serde_rountrip() {
        let mut rng = thread_rng();
        let note = Note::from_parts(
            Address::dummy(&mut rng),
            Address::dummy(&mut rng),
            Value {
                amount: 10u64.into(),
                asset_id: Id(Fq::from(1u64)),
            },
            Rseed::generate(&mut rng),
        )
        .expect("hardcoded note");

        let note_serialized = serde_json::to_vec(&note).unwrap();
        let note_deserialized = serde_json::from_slice(&note_serialized).unwrap();
        assert_eq!(note, note_deserialized);
    }

    #[test]
    fn test_fq_roundtrip() {
        let mut rng = thread_rng();
        let note = Note::from_parts(
            Address::dummy(&mut rng),
            Address::dummy(&mut rng),
            Value {
                amount: 10u64.into(),
                asset_id: Id(Fq::from(1u64)),
            },
            Rseed::generate(&mut rng),
        )
        .expect("hardcoded note");

        let note_serialized: Vec<u8> = serde_json::to_vec(&note).unwrap();
        println!("length 1 {}", note_serialized.len());
        let fq_vec = u8_slice_to_fq_vec(&note_serialized);
        let decoded_serialized_note = fq_vec_to_u8_slice(&fq_vec);
        println!("length 2 {}", decoded_serialized_note.len());
        assert_eq!(note_serialized, decoded_serialized_note);

        let note_deserialized: Note = serde_json::from_slice(&decoded_serialized_note).unwrap();

        assert_eq!(note, note_deserialized);
    }

    /// Converts an arbitrary slice of u8 into a Vec<Fq>, each u8 mapping to an Fq element.
    /// This is a bijective mapping because every u8 (0..=255) is well within the field range.
    pub fn u8_slice_to_fq_vec(data: &[u8]) -> Vec<Fq> {
        // We use Fq::from(u64) which is available (as seen in other parts of the code).
        data.iter().map(|&b| Fq::from(u64::from(b))).collect()
    }

    /// Converts a Vec<Fq> back into a Vec<u8>. This function will panic if any element
    /// is not in the range 0..=255 (which shouldn't happen if you only constructed the
    /// Fq elements using u8_slice_to_fq_vec).
    pub fn fq_vec_to_u8_slice(fqs: &[Fq]) -> Vec<u8> {
        fqs.iter()
            .map(|fq| {
                // Convert the field element to its canonical little-endian bytes.
                let bytes = fq.to_bytes();
                // Ensure that the bytes representing high-order digits are all zero,
                // so that the element really fits in a u8.
                // (Our Fq elements come out as a 32-byte array; all bytes beyond the 0-th should be zero.)
                if bytes[1..].iter().any(|&b| b != 0) {
                    panic!("Fq element out of u8 range!");
                }
                bytes[0]
            })
            .collect()
    }

    #[test]
    pub fn bijectivity_test() -> anyhow::Result<()> {
        let mut rng = rand::thread_rng();

        for _ in 0..100 {
            let mut bytes = [0u8; 32];
    
            // Fill the first 31 bytes with arbitrary values.
            rng.fill_bytes(&mut bytes[0..31]);
    
            // To make sure out values lie outside the canonical range, we set the top 3 bits to all 1's (top 8 actually)
            bytes[31] = 0x0F;
    
            // Decode using the canonical checker, which enforces that the bytes are fully reduced.
            let fq = Fq::from_le_bytes_mod_order(&bytes);
    
            // Re-encode the field element. This must yield exactly the same canonical bytes.
            let encoded = fq.to_bytes();
            assert_eq!(encoded, bytes, "Round-trip canonical encoding failed.");
        }

        Ok(())
    }

    #[test]
    fn test_canonical_note_roundtrip() {
        let mut rng = thread_rng();

        for _ in 0..1000 {
            let original_note = Note::from_parts(
                penumbra_keys::test_keys::ADDRESS_1.clone(),
                penumbra_keys::test_keys::ADDRESS_0.clone(),
                Value {
                    amount: 10u64.into(),
                    asset_id: Id(Fq::from(1u64)),
                },
                Rseed::generate(&mut rng),
            )
            .expect("hardcoded note");

            // Canonically encode the note: this produces a Vec<Vec<Fq>> containing the field-element encodings.
            let note_fqs = original_note.canonical_encoding();

            // Decode the note by inverting the canonical encoding.
            let decoded_note = Note::canonical_decoding(&note_fqs).unwrap();

            // Assert the round-trip was successful.
            assert_eq!(original_note, decoded_note);
        }
    }
}
