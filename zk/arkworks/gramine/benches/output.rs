use std::str::FromStr;

use ark_ff::Field;
use ark_groth16::ProvingKey;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisMode,
};
use criterion::{criterion_group, criterion_main, Criterion};
use decaf377::{Bls12_377, Fq, Fr};
use decaf377_fmd as fmd;
use decaf377_ka as ka;
use once_cell::sync::Lazy;
use penumbra_asset::{asset, Value};
use penumbra_keys::{keys::{Bip44Path, Diversifier, SeedPhrase, SpendKey}, Address};
use penumbra_num::Amount;
use penumbra_proof_params::{DummyWitness, LazyProvingKey};
use penumbra_shielded_pool::Rseed;
use rand_core::OsRng;

use arkworks_gramine::{
    note::Note,
    proof_params::OUTPUT_PROOF_PROVING_KEY,
    output::proof::{
    OutputProof, OutputProofPublic, OutputProofPrivate, OutputCircuit
    }
};


fn prove(r: Fq, s: Fq, public: OutputProofPublic, private: OutputProofPrivate) {
    use std::io::Write;
    eprintln!("Starting proof generation...");
    std::io::stderr().flush().unwrap();

    let start = std::time::Instant::now();

    let _proof = OutputProof::prove(r, s, &OUTPUT_PROOF_PROVING_KEY, public, private)
        .expect("can generate proof");

    eprintln!("Proof generation took: {:?}", start.elapsed());
    std::io::stderr().flush().unwrap();
    
}

fn output_proving_time(c: &mut Criterion) {
    // Create two addresses (debtor and creditor)
    let seed_phrase_1 = SeedPhrase::from_randomness(&[1u8; 32]);
    let seed_phrase_2 = SeedPhrase::from_randomness(&[2u8; 32]);
    
    let sk_debtor = SpendKey::from_seed_phrase_bip44(seed_phrase_1, &Bip44Path::new(0));
    let sk_creditor = SpendKey::from_seed_phrase_bip44(seed_phrase_2, &Bip44Path::new(0));
    
    let debtor_addr = {
        let fvk = sk_debtor.full_viewing_key();
        let ivk = fvk.incoming();
        ivk.payment_address(0u32.into()).0
    };
    
    let creditor_addr = {
        let fvk = sk_creditor.full_viewing_key();
        let ivk = fvk.incoming();
        ivk.payment_address(0u32.into()).0
    };

    let spend_auth_randomizer = Fr::from(1u64);
    let rk = sk_debtor.spend_auth_key().randomize(&spend_auth_randomizer).into();
    let ak = sk_debtor.spend_auth_key().into();
    let nk = *sk_debtor.nullifier_key();

    let value_to_send = Value {
        amount: Amount::from(1000u64),
        asset_id: asset::Id(Fq::from(1u64)),
    };

    let note = Note::from_parts(
        debtor_addr,
        creditor_addr,
        value_to_send,
        Rseed([1u8; 32]),
    ).expect("can make a note");
    
    let note_commitment = note.commit();

    let public = OutputProofPublic {
        note_commitment,
        rk,
    };
    let private = OutputProofPrivate {
        note,
        spend_auth_randomizer,
        ak,
        nk,
    };

    let r = Fq::rand(&mut OsRng);
    let s = Fq::rand(&mut OsRng);

    c.bench_function("output proving", |b| {
        b.iter(|| prove(r, s, public.clone(), private.clone()))
    });

    // Also print out the number of constraints
    let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);

    let circuit = OutputCircuit::with_dummy_witness();
    circuit
        .generate_constraints(cs.clone())
        .expect("can generate constraints");
    cs.finalize();
    let num_constraints = cs.num_constraints();
    println!("Number of constraints: {}", num_constraints);
}

fn sanity_check(c: &mut Criterion) {
    c.bench_function("sanity check", |b| b.iter(|| 2 + 2));
}

criterion_group!(benches, sanity_check, output_proving_time);

// criterion_group!(benches, output_proving_time);
criterion_main!(benches);