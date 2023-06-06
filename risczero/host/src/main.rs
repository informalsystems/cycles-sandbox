use methods::{MTCS_CHECK_ELF, MTCS_CHECK_ID};
use mtcs_core::SimpleSetOff;
use risc0_zkvm::{serde, Executor, ExecutorEnv};

fn main() {
    // First, we construct an executor environment
    let env = ExecutorEnv::builder()
        .add_input(
            &serde::to_vec(&vec![
                SimpleSetOff {
                    id: None,
                    debtor: 1,
                    creditor: 2,
                    amount: 100,
                    set_off: 70,
                    remainder: 30,
                },
                SimpleSetOff {
                    id: None,
                    debtor: 2,
                    creditor: 3,
                    amount: 100,
                    set_off: 70,
                    remainder: 30,
                },
                SimpleSetOff {
                    id: None,
                    debtor: 3,
                    creditor: 1,
                    amount: 70,
                    set_off: 70,
                    remainder: 0,
                },
            ])
            .unwrap(),
        )
        .build();

    let now = std::time::Instant::now();

    // Next, we make an executor, loading the (renamed) ELF binary.
    println!("Starting executor...");
    let mut exec = Executor::from_elf(env, MTCS_CHECK_ELF).unwrap();

    // Run the executor to produce a session.
    println!("Running executor...");
    let session = exec.run().unwrap();

    // Prove the session to produce a receipt.
    println!("Proving session...");
    let receipt = session.prove().unwrap();

    let proof_time = now.elapsed();
    println!("Proof generation time: {:?}", proof_time);

    // TODO: Implement code for transmitting or serializing the receipt for
    // other parties to verify here

    // Optional: Verify receipt to confirm that recipients will also be able to
    // verify your receipt
    receipt.verify(MTCS_CHECK_ID).unwrap();
    println!("Verification time: {:?}", now.elapsed() - proof_time);
}
