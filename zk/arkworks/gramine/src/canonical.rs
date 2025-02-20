use ark_ff::ToConstraintField;
use decaf377::Fq;
use penumbra_asset::Value;
use penumbra_keys::Address;
use penumbra_num::Amount;
use penumbra_shielded_pool::Rseed;

use crate::note::Note;

pub trait CanonicalFqEncoding {
    fn canonical_encoding(&self) -> Vec<Fq>;
}

pub trait CanonicalFqDecoding {
    fn canonical_decoding(fqs: &[Fq]) -> anyhow::Result<Self>
    where
        Self: Sized;
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
/// The slice must contain exactly **10** `Fq` elements:
/// - `fqs[0..2]` for [`Value`]
/// - `fqs[2..4]` for [`Rseed`]
/// - `fqs[4..7]` for the debtor [`Address`]
/// - `fqs[7..10]` for the creditor [`Address`]
impl CanonicalFqDecoding for Note {
    fn canonical_decoding(fqs: &[Fq]) -> anyhow::Result<Note> {
        if fqs.len() != 10 {
            return Err(anyhow::anyhow!(
                "Expected 10 Fq elements for Note, got {}",
                fqs.len()
            ));
        }

        let value_encoded = &fqs[0..2];
        let rseed_encoded = &fqs[2..4];
        let debtor_encoded = &fqs[4..7];
        let creditor_encoded = &fqs[7..10];

        let value = Value::canonical_decoding(value_encoded)?;

        // For Rseed, we use our bijective mapping from 32-byte encoding into 2 × Fq.
        let rseed = Rseed(<[u8; 32]>::canonical_decoding(rseed_encoded)?);

        let debtor = Address::canonical_decoding(debtor_encoded)?;
        let creditor = Address::canonical_decoding(creditor_encoded)?;

        Note::from_parts(debtor, creditor, value, rseed).map_err(Into::into)
    }
}

impl CanonicalFqEncoding for Address {
    fn canonical_encoding(&self) -> Vec<Fq> {
        let address_bytes = self.to_vec();
        assert_eq!(
            address_bytes.len(),
            80,
            "Address bytes must be exactly 80 bytes"
        );

        let fq1 = {
            let mut arr = [0u8; 32];
            // first 30 bytes
            arr[..30].copy_from_slice(&address_bytes[0..30]);
            Fq::from_le_bytes_mod_order(&arr)
        };

        let fq2 = {
            let mut arr = [0u8; 32];
            // next 30 bytes
            arr[..30].copy_from_slice(&address_bytes[30..60]);
            Fq::from_le_bytes_mod_order(&arr)
        };

        let fq3 = {
            let mut arr = [0u8; 32];
            // final 20 bytes
            arr[..20].copy_from_slice(&address_bytes[60..80]);
            Fq::from_le_bytes_mod_order(&arr)
        };

        vec![fq1, fq2, fq3]
    }
}

/// Decodes an [`Address`] from its canonical encoding as 3 [`Fq`] elements.
///
/// Addresses are serialized to a constant 80 bytes. The 3 field elements represent
/// the first 30 bytes, second 30 bytes, and last 20 bytes.
///
/// Returns an error if:
/// - The slice length is not exactly 4.
/// - Constructing an [`Address`] from a byte array fails
impl CanonicalFqDecoding for Address {
    fn canonical_decoding(fqs: &[Fq]) -> anyhow::Result<Address> {
        if fqs.len() != 3 {
            return Err(anyhow::anyhow!(
                "Expected 3 Fq elements for Address decoding, got {}",
                fqs.len()
            ));
        }

        let bytes1 = fqs[0].to_bytes();
        let bytes2 = fqs[1].to_bytes();
        let bytes3 = fqs[2].to_bytes();

        // Prepare an 80-byte buffer for the original address.
        let mut addr_bytes = [0u8; 80];
        addr_bytes[..30].copy_from_slice(&bytes1[..30]);
        addr_bytes[30..60].copy_from_slice(&bytes2[..30]);
        addr_bytes[60..80].copy_from_slice(&bytes3[..20]);

        // Reconstruct the Address from the 80-byte representation
        Address::try_from(addr_bytes.into_iter().collect::<Vec<u8>>())
    }
}

impl CanonicalFqEncoding for Value {
    fn canonical_encoding(&self) -> Vec<Fq> {
        let amount = self
            .amount
            .to_field_elements()
            .expect("expect amount encoding");
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

        let amount_bytes: [u8; 16] = fqs[0].to_bytes()[..16]
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
        let mut bottom_bytes = *self;
        bottom_bytes[31] = 0u8;
        let mut top_bytes = [0u8; 32];
        top_bytes[0] = self[31];

        vec![
            Fq::from_le_bytes_mod_order(&bottom_bytes),
            Fq::from_le_bytes_mod_order(&top_bytes),
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
