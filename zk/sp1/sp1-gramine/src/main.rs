use sp1_sdk::{ProverClient, SP1Stdin};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const FIBONACCI_ELF: &[u8] = include_bytes!("../data/riscv32im-succinct-zkvm-elf");

#[derive(Debug)]
pub struct VerifierParams {
    pub proof: String,
    pub verifying_key: String,
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Setup the prover client.
    let client = ProverClient::new();

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    stdin.write(&2u32);

    // Setup the program for proving.
    let (pk, vk) = client.setup(FIBONACCI_ELF);

    // Generate the proof
    let proof = client
        .prove(&pk, stdin)
        .run()
        .expect("failed to generate proof");

    println!("Successfully generated proof!");

    let output = VerifierParams {
        proof: bincode_serialize_hex(proof),
        verifying_key: bincode_serialize_hex(vk),
    };
    println!("{output:#?}");
}

fn bincode_serialize_hex(value: impl serde::Serialize) -> String {
    let vk_bytes: Vec<u8> = bincode::serialize(&value).expect("infallible serializer");
    hex::encode(vk_bytes)
}
