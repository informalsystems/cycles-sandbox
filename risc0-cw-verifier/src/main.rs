use risc0_zkp::core::digest::Digest;
use risc0_zkvm::{ExitCode, InnerReceipt, Journal, Receipt, ReceiptClaim, SystemState};

fn main() {
    // create dummy receipt
    // TODO: replace this with code for deserializing a real receipt
    let receipt = Receipt {
        inner: InnerReceipt::Fake {
            claim: ReceiptClaim {
                pre: SystemState {
                    pc: 0,
                    merkle_root: Digest::ZERO,
                }
                .into(),
                post: SystemState {
                    pc: 0,
                    merkle_root: Digest::ZERO,
                }
                .into(),
                exit_code: ExitCode::Halted(0),
                input: Digest::ZERO.into(),
                output: None.into(),
            },
        },
        journal: Journal { bytes: vec![] },
    };

    // Verify receipt, panic if it's wrong
    receipt
        .verify(Digest::ZERO)
        .expect("dummy receipt fails to verify");
}
