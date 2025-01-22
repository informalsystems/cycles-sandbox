#![deny(clippy::unwrap_used)]
#![allow(clippy::redundant_static_lifetimes)]
// Requires nightly.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

use anyhow::{bail, Result};
use ark_groth16::{PreparedVerifyingKey, ProvingKey, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use decaf377::Bls12_377;
use once_cell::sync::{Lazy, OnceCell};
use std::ops::Deref;

/// The length of our Groth16 proofs in bytes.
pub const GROTH16_PROOF_LENGTH_BYTES: usize = 192;

// TODO: can this import be removed?
use crate::traits::ProvingKeyExt;

/// A wrapper around a proving key that can be lazily loaded.
///
/// One instance of this struct is created for each proving key.
///
/// The behavior of those instances is controlled by the `bundled-proving-keys`
/// feature. When the feature is enabled, the proving key data is bundled into
/// the binary at compile time, and the proving key is loaded from the bundled
/// data on first use.  When the feature is not enabled, the proving key must be
/// loaded using `try_load` prior to its first use.
///
/// The `bundled-proving-keys` feature needs access to proving keys at build
/// time.  When pulling the crate as a dependency, these may not be available.
/// To address this, the `download-proving-keys` feature will download them from
/// the network at build time. All proving keys are checked against hardcoded hashes
/// to ensure they have not been tampered with.
#[derive(Debug, Default)]
pub struct LazyProvingKey {
    pk_id: &'static str,
    inner: OnceCell<ProvingKey<Bls12_377>>,
}

impl LazyProvingKey {
    // Not making this pub means only the statically defined proving keys can exist.
    fn new(pk_id: &'static str) -> Self {
        LazyProvingKey {
            pk_id,
            inner: OnceCell::new(),
        }
    }

    /// Attempt to load the proving key from the given bytes.
    ///
    /// The provided bytes are validated against a hardcoded hash of the expected proving key,
    /// so passing the wrong proving key will fail.
    ///
    /// If the proving key is already loaded, this method is a no-op.
    pub fn try_load(&self, bytes: &[u8]) -> Result<&ProvingKey<Bls12_377>> {
        self.inner.get_or_try_init(|| {
            let pk = ProvingKey::deserialize_uncompressed_unchecked(bytes)?;

            let pk_id = pk.debug_id();
            if pk_id != self.pk_id {
                bail!(
                    "proving key ID mismatch: expected {}, loaded {}",
                    self.pk_id,
                    pk_id
                );
            }

            Ok(pk)
        })
    }

    /// Attempt to load the proving key from the given bytes.
    ///
    /// This method bypasses the validation checks against the hardcoded
    /// hash of the expected proving key.
    pub fn try_load_unchecked(&self, bytes: &[u8]) -> Result<&ProvingKey<Bls12_377>> {
        self.inner.get_or_try_init(|| {
            let pk = ProvingKey::deserialize_uncompressed_unchecked(bytes)?;

            Ok(pk)
        })
    }
}

impl Deref for LazyProvingKey {
    type Target = ProvingKey<Bls12_377>;

    fn deref(&self) -> &Self::Target {
        self.inner.get().expect("Proving key cannot be loaded!")
    }
}

// TODO: import this from respective modules
pub const OUTPUT_PROVING_KEY_ID: &'static str = "groth16pk1t79udfwlmjkmtvlm8k8lmwd6qs354r40axa9895zeayz08xz04xq7lm0gq";
pub const SETTLEMENT_PROVING_KEY_ID: &'static str = "groth16pk1n3klwt4jz9rxduf6nuqxazycu96w99cuyq2tzsgdsmudaqul5a0sdt9gm6";

// Note: Conditionally load the proving key objects if the
// bundled-proving-keys is present.

/// Proving key for the settlement proof.
pub static SETTLEMENT_PROOF_PROVING_KEY: Lazy<LazyProvingKey> = Lazy::new(|| {
    let settlement_proving_key = LazyProvingKey::new(SETTLEMENT_PROVING_KEY_ID);

    #[cfg(feature = "bundled-proving-keys")]
    settlement_proving_key
        .try_load(include_bytes!("../gen/settlement_pk.bin"))
        .expect("bundled proving key is valid");

    settlement_proving_key
});

/// Verification key for the settlement proof.
pub static SETTLEMENT_PROOF_VERIFICATION_KEY: Lazy<PreparedVerifyingKey<Bls12_377>> =
    Lazy::new(|| settlement_verification_parameters().into());

pub mod settle {
    include!("../gen/settlement_id.rs");
}


/// Proving key for the output proof.
pub static OUTPUT_PROOF_PROVING_KEY: Lazy<LazyProvingKey> = Lazy::new(|| {
    let output_proving_key = LazyProvingKey::new(OUTPUT_PROVING_KEY_ID);
    println!("Checking proving key...");

    #[cfg(feature = "bundled-proving-keys")]
    output_proving_key
        .try_load(include_bytes!("../gen/output_pk.bin"))
        .expect("bundled proving key is valid");

    println!("Proving key loaded successfully");
    output_proving_key
});

/// Verification key for the output proof.
pub static OUTPUT_PROOF_VERIFICATION_KEY: Lazy<PreparedVerifyingKey<Bls12_377>> =
    Lazy::new(|| output_verification_parameters().into());

pub mod output {
    include!("../gen/output_id.rs");
}

// Note: Here we are using `CanonicalDeserialize::deserialize_uncompressed_unchecked` as the
// parameters are being loaded from a trusted source (our source code).

fn settlement_verification_parameters() -> VerifyingKey<Bls12_377> {
    let vk_params = include_bytes!("../gen/settlement_vk.param");
    VerifyingKey::deserialize_uncompressed_unchecked(&vk_params[..])
        .expect("can deserialize VerifyingKey")
}

fn output_verification_parameters() -> VerifyingKey<Bls12_377> {
    let vk_params = include_bytes!("../gen/settlement_vk.param");
    VerifyingKey::deserialize_uncompressed_unchecked(&vk_params[..])
        .expect("can deserialize VerifyingKey")
}
