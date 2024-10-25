use cosmwasm_std::Binary;
use sp1_cw::msg::ExecuteMsg;
use sp1_sdk::{ProverClient, SP1Stdin};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const ELF: &[u8] = include_bytes!("../data/riscv32im-succinct-zkvm-elf");

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();

    // Setup the prover client.
    let client = ProverClient::new();

    // Setup the inputs.
    let mut stdin = SP1Stdin::new();
    stdin.write(&2u32);

    // Setup the program for proving.
    let (pk, vk) = client.setup(ELF);

    // Generate the proof
    let proof = client
        .prove(&pk, stdin)
        .run()
        .expect("failed to generate proof");

    let verify_proof_msg = ExecuteMsg::VerifyProof {
        proof_bytes: bin_serialize(proof),
        verifying_key_bytes: bin_serialize(vk),
    };

    println!(
        "{}",
        serde_json::to_string(&verify_proof_msg).expect("infallible serializer")
    );
}

fn bin_serialize(value: impl serde::Serialize) -> Binary {
    let bytes: Vec<u8> = bincode::serialize(&value).expect("infallible serializer");
    bytes.into()
}
