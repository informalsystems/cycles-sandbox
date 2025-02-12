use ark_ff::ToConstraintField;
use decaf377::Fq;
use decaf377_ka as ka;
use penumbra_asset::Value;
use penumbra_keys::keys::{Diversifier, DIVERSIFIER_LEN_BYTES};
use penumbra_keys::Address;
use penumbra_num::Amount;
use penumbra_shielded_pool::Rseed;

use crate::note::Note;

pub trait CanonicalFqEncoding {
    fn canonical_encoding(&self) -> Vec<Fq>;
}

pub trait CanonicalFqDecoding {
    fn canonical_decoding(fqs: &[Fq]) -> anyhow::Result<Self> where Self: Sized;
}

impl CanonicalFqEncoding for Note {
    fn canonical_encoding(&self) -> Vec<Fq> {
        let mut value_encoded = self.value().to_field_elements().unwrap();
        let mut rseed_encoded = self.rseed().0.canonical_encoding(); // [u8; 32] -> [Fq; 2] conversion
        let mut debtor_encoded = self.debtor().canonical_encoding();
        let mut creditor_encoded = self.creditor().canonical_encoding();
        
        let mut res = Vec::new();
        res.append(&mut value_encoded);
        res.append(&mut rseed_encoded);
        res.append(&mut debtor_encoded);
        res.append(&mut creditor_encoded);

        res
    }
}

/// Implements the canonical decoding of a `Note` from a slice of field elements.
/// 
/// The slice must contain exactly **12** `Fq` elements:
/// - `fqs[0..2]` for [`Value`]
/// - `fqs[2..4]` for [`Rseed`]
/// - `fqs[4..8]` for the debtor [`Address`]
/// - `fqs[8..12]` for the creditor [`Address`]
impl CanonicalFqDecoding for Note {
    fn canonical_decoding(fqs: &[Fq]) -> anyhow::Result<Note> {
        if fqs.len() != 12 {
            return Err(anyhow::anyhow!("Expected 12 Fq elements for Note, got {}", fqs.len()));
        }
    
        let value_encoded = &fqs[0..2];
        let rseed_encoded = &fqs[2..4];
        let debtor_encoded = &fqs[4..8];
        let creditor_encoded = &fqs[8..12];
    
        let value = Value::canonical_decoding(value_encoded)?;
    
        // For Rseed, we use our bijective mapping from 32-byte encoding into 2 × Fq.
        let rseed = Rseed(<[u8; 32]>::canonical_decoding(&rseed_encoded)?);
    
        let debtor = Address::canonical_decoding(debtor_encoded)?;
        let creditor = Address::canonical_decoding(creditor_encoded)?;
    
        Note::from_parts(debtor, creditor, value, rseed).map_err(Into::into)
    }
}

impl CanonicalFqEncoding for Address {
    fn canonical_encoding(&self) -> Vec<Fq> {
        // Store the [u8; 16] diversifier bytes as an Fq
        let diversifier = Fq::from_le_bytes_mod_order(&self.diversifier().0);
        let pkd = self.transmission_key_s().clone();
        let cluekey = self.clue_key().0.canonical_encoding(); // [u8; 32] -> [Fq; 2] conversion
        
        vec![diversifier, pkd, cluekey[0], cluekey[1]]
    }
}

/// Implements the canonical decoding of an [`Address`] from a slice of [`Fq`] elements.
///
/// The slice must contain exactly **4** `Fq` elements:
/// - `fqs[0]`: Encodes the diversifier. Only the first `DIVERSIFIER_LEN_BYTES` of its canonical bytes
///   are used to form a [`Diversifier`].
/// - `fqs[1]`: Encodes the transmission key, whose canonical bytes are used as the public key component.
/// - `fqs[2]` and `fqs[3]`: Together, these two elements encode the clue key via our bijective mapping.
///
/// # Errors
///
/// Returns an error if:
/// - The slice length is not exactly 4.
/// - Converting the diversifier field into the required fixed-size array fails.
/// - Constructing an [`Address`] from its components fails.
impl CanonicalFqDecoding for Address {
    fn canonical_decoding(fqs: &[Fq]) -> anyhow::Result<Address> {
        if fqs.len() != 4 {
            return Err(anyhow::anyhow!(
                "Expected 4 Fq elements for Address, got {}",
                fqs.len()
            ));
        }
        let diversifier_fq = fqs[0];
        let transmission_fq = fqs[1];
        let clue_key_fqs = &fqs[2..4];
        
        let diversifier_bytes: [u8; DIVERSIFIER_LEN_BYTES] = diversifier_fq
            .to_bytes()[..DIVERSIFIER_LEN_BYTES]
            .try_into()
            .map_err(|_| anyhow::anyhow!("slice length must be DIVERSIFIER_LEN_BYTES for diversifier"))?;

        let d = Diversifier(diversifier_bytes);
        let pk_d = ka::Public(transmission_fq.to_bytes());
        let ck_d = decaf377_fmd::ClueKey(<[u8; 32]>::canonical_decoding(&clue_key_fqs)?);
        
        Address::from_components(d, pk_d, ck_d)
            .ok_or_else(|| anyhow::anyhow!("couldn't build Address from components"))
    }
}


impl CanonicalFqEncoding for Value {
    fn canonical_encoding(&self) -> Vec<Fq> {
        let amount = self.amount.to_field_elements().expect("expect amount encoding");
        assert_eq!(amount.len(), 1);
        let id = self.asset_id.0;

        vec![amount[0], id]
    }
}

/// Implements the canonical decoding of a [`Value`] from a slice of [`Fq`] elements.
///
/// The slice must contain exactly **2** `Fq` elements:
/// - `fqs[0]`: Encodes the `Amount`, where the first 16 bytes (in little-endian order) represent a `u128`.
/// - `fqs[1]`: Encodes the asset identifier, wrapped in the [`Id`] type.
///
/// # Errors
///
/// Returns an error if:
/// - The slice length is not exactly 2.
/// - Converting the first element into a 16-byte slice fails.
impl CanonicalFqDecoding for Value {
    fn canonical_decoding(fqs: &[Fq]) -> anyhow::Result<Value> {
        use penumbra_asset::asset::Id;

        // Expecting two Fq elements:
        // - the first encodes the first 16 bytes of the u128 (little endian)
        // - the second encodes the asset id.
        if fqs.len() != 2 {
            return Err(anyhow::anyhow!(
                "Expected 2 Fq elements for Value, got {}",
                fqs.len()
            ));
        }

        let amount_bytes: [u8; 16] = fqs[0]
            .to_bytes()[..16]
            .try_into()
            .map_err(|_| anyhow::anyhow!("slice length must be 16 for Amount"))?;
        let amount = Amount::from_le_bytes(amount_bytes);
        let asset_id = Id(fqs[1]);
        
        Ok(Value { amount, asset_id })
    }
}

/// Implements a bijective canonical encoding for a 32-byte array into two [`Fq`] elements.
///
/// Because [`Fq::from_le_bytes_mod_order`] reduces modulo the field modulus (which is 2^253),
/// using it directly on 32 bytes is lossy. We split the array into:
///
/// - The first 31 bytes (with the 32nd byte zeroed), and
/// - The original 32nd byte (stored as the LSB in a separate 32-byte array).
///
/// This mapping is reversible via [`CanonicalFqDecoding`]
impl CanonicalFqEncoding for [u8; 32] {
    fn canonical_encoding(&self) -> Vec<Fq> {
        let mut bottom_bytes = self.clone();
        bottom_bytes[31] = 0u8;
        let mut top_bytes = [0u8; 32];
        top_bytes[0] = self[31];
    
        vec![
            Fq::from_le_bytes_mod_order(&bottom_bytes),
            Fq::from_le_bytes_mod_order(&top_bytes)
        ]
    }
}

/// Reconstructs a `[u8; 32]` from two [`Fq`] elements produced by [`CanonicalFqEncoding`].
///
/// The first Fq recovers the lower 31 bytes and the second Fq recovers the original 32nd byte.
impl CanonicalFqDecoding for [u8; 32] {
    fn canonical_decoding(fqs: &[Fq]) -> anyhow::Result<[u8; 32]> {
        let bottom_bytes = fqs[0].to_bytes();
        let top_bytes = fqs[1].to_bytes();
    
        let mut bytes = [0u8; 32];
        // The original lower 31 bytes will be the lower 31 bytes of bottom_bytes.
        bytes[..31].copy_from_slice(&bottom_bytes[..31]);
        // The original 32nd byte is stored in the least-significant position of top_bytes
        bytes[31] = top_bytes[0];
    
        Ok(bytes)
    }
}