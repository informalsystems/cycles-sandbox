use anyhow::Error;
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_serialize::CanonicalSerialize;
use decaf377::Bls12_377;
use penumbra_proof_params::{
    generate_constraint_matrices, DummyWitness, ProvingKeyExt, VerifyingKeyExt,
};
use penumbra_proof_setup::single::{
    circuit_degree, combine, log::Hashable, transition, Phase1CRSElements, Phase1Contribution,
    Phase2Contribution,
};
use rand_core::OsRng;
use std::fs;
use std::io::BufWriter;
use std::path::PathBuf;

use crate::output::OutputCircuit;
use crate::settlement::SettlementCircuit;

pub mod note;
pub mod nullifier;
pub mod output;
pub mod proof_bundle;
pub mod settlement;

fn generate_parameters<D: DummyWitness>() -> (ProvingKey<Bls12_377>, VerifyingKey<Bls12_377>) {
    let matrices = generate_constraint_matrices::<D>();

    let mut rng = OsRng;

    let degree = circuit_degree(&matrices).expect("failed to calculate degree of circuit");
    let phase1root = Phase1CRSElements::root(degree);

    // Doing two contributions to make sure there's not some weird bug there
    let phase1contribution = Phase1Contribution::make(&mut rng, phase1root.hash(), &phase1root);
    let phase1contribution = Phase1Contribution::make(
        &mut rng,
        phase1contribution.hash(),
        &phase1contribution.new_elements,
    );

    let (extra, phase2root) = transition(&phase1contribution.new_elements, &matrices)
        .expect("failed to transition between setup phases");

    let phase2contribution = Phase2Contribution::make(&mut rng, phase2root.hash(), &phase2root);
    let phase2contribution = Phase2Contribution::make(
        &mut rng,
        phase2contribution.hash(),
        &phase2contribution.new_elements,
    );

    let pk = combine(
        &matrices,
        &phase1contribution.new_elements,
        &phase2contribution.new_elements,
        &extra,
    );

    let vk = pk.vk.clone();

    (pk, vk)
}

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    println!("{}", root.display());
    let target_dir = root.join("gen");
    println!("{}", target_dir.display());

    let (output_pk, output_vk) = generate_parameters::<OutputCircuit>();
    write_params(&target_dir, "output", &output_pk, &output_vk).expect("write failure");

    let (settlement_pk, settlement_vk) = generate_parameters::<SettlementCircuit>();
    write_params(&target_dir, "settlement", &settlement_pk, &settlement_vk).expect("write failure");
}

fn write_params(
    target_dir: &PathBuf,
    name: &str,
    pk: &ProvingKey<Bls12_377>,
    vk: &VerifyingKey<Bls12_377>,
) -> Result<(), Error> {
    let pk_location = target_dir.join(format!("{}_pk.bin", name));
    let vk_location = target_dir.join(format!("{}_vk.param", name));
    let id_location = target_dir.join(format!("{}_id.rs", name));

    let pk_file = fs::File::create(&pk_location)?;
    let vk_file = fs::File::create(&vk_location)?;

    let pk_writer = BufWriter::new(pk_file);
    let vk_writer = BufWriter::new(vk_file);

    ProvingKey::serialize_uncompressed(pk, pk_writer).expect("can serialize ProvingKey");
    VerifyingKey::serialize_uncompressed(vk, vk_writer).expect("can serialize VerifyingKey");

    let pk_id = pk.debug_id();
    let vk_id = vk.debug_id();
    std::fs::write(
        id_location,
        format!(
            r#"
pub const PROVING_KEY_ID: &'static str = "{pk_id}";
pub const VERIFICATION_KEY_ID: &'static str = "{vk_id}";
"#,
        ),
    )?;

    Ok(())
}
