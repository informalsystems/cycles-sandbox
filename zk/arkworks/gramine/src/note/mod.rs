use decaf377::Fq;
use decaf377_fmd as fmd;
use once_cell::sync::Lazy;
use penumbra_asset::{asset, Value};
use penumbra_keys::Address;
use penumbra_num::Amount;
use penumbra_shielded_pool::note::Error;
use penumbra_shielded_pool::Rseed;
use penumbra_tct::StateCommitment;

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
    address: Address,
    /// The s-component of the transmission key of the destination address.
    /// We store this separately to ensure that every `Note` is constructed
    /// with a valid transmission key (the `ka::Public` does not validate
    /// the curve point until it is used, since validation is not free).
    transmission_key_s: Fq,
}

impl Note {
    pub fn from_parts(address: Address, value: Value, rseed: Rseed) -> Result<Self, Error> {
        Ok(Self {
            value,
            rseed,
            address: address.clone(),
            transmission_key_s: Fq::from_bytes_checked(&address.transmission_key().0)
                .map_err(|_| Error::InvalidTransmissionKey)?,
        })
    }

    pub fn address(&self) -> Address {
        self.address.clone()
    }

    pub fn note_blinding(&self) -> Fq {
        self.rseed.derive_note_blinding()
    }

    pub fn value(&self) -> Value {
        self.value
    }

    pub fn diversified_generator(&self) -> decaf377::Element {
        self.address.diversifier().diversified_generator()
    }

    pub fn transmission_key_s(&self) -> Fq {
        self.transmission_key_s
    }

    pub fn clue_key(&self) -> &fmd::ClueKey {
        self.address.clue_key()
    }

    pub fn commit(&self) -> StateCommitment {
        self::commitment(
            self.note_blinding(),
            self.value,
            self.diversified_generator(),
            self.transmission_key_s,
            self.address.clue_key(),
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
            .field("address", &self.address())
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
) -> StateCommitment {
    let commit = poseidon377::hash_6(
        &NOTECOMMIT_DOMAIN_SEP,
        (
            note_blinding,
            value.amount.into(),
            value.asset_id.0,
            diversified_generator.vartime_compress_to_field(),
            transmission_key_s,
            Fq::from_le_bytes_mod_order(&clue_key.0[..]),
        ),
    );

    StateCommitment(commit)
}
