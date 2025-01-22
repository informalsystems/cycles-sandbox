use std::str::FromStr;

use ark_ff::Field;
use arkworks_merkle_tree::poseidontree::Poseidon377MerkleTree;
use criterion::{criterion_group, criterion_main, Criterion};
use decaf377::Fq;
use decaf377_fmd as fmd;
use decaf377_ka as ka;
use penumbra_asset::{asset, Value};
use penumbra_keys::{keys::{Bip44Path, Diversifier, SeedPhrase, SpendKey}, Address};
use penumbra_num::Amount;
use penumbra_proof_params::DummyWitness;
use penumbra_shielded_pool::Rseed;
use rand_core::OsRng;
use ark_relations::r1cs::{ConstraintSystem, OptimizationGoal, SynthesisMode, ConstraintSynthesizer};

use arkworks_gramine::{
    settlement::proof::{
        SettlementProof, SettlementProofPublic, SettlementProofPrivate, 
        SettlementProofConst, SettlementCircuit
    },
    note::Note,
    nullifier::Nullifier,
    proof_params::SETTLEMENT_PROOF_PROVING_KEY
};

fn address_from_seed(seed_phrase_randomness: &[u8], index: u32) -> Address {
    let seed_phrase = SeedPhrase::from_randomness(&seed_phrase_randomness);
    let sk_recipient = SpendKey::from_seed_phrase_bip44(seed_phrase, &Bip44Path::new(0));
    let fvk_recipient = sk_recipient.full_viewing_key();
    let ivk_recipient = fvk_recipient.incoming();
    let (dest, _dtk_d) = ivk_recipient.payment_address(index.into());
    dest
}

fn prove(r: Fq, s: Fq, public: SettlementProofPublic, private: SettlementProofPrivate) {
    println!("Starting proof generation...");
        
    let proof = SettlementProof::prove(r, s, &SETTLEMENT_PROOF_PROVING_KEY, public, private)
        .expect("can generate proof");
}


fn settlement_proving_time(c: &mut Criterion) {
    // Generate deterministic test data similar to the proptest
    let seed_phrase_randomness_1 = [1u8; 32];
    let seed_phrase_randomness_2 = [2u8; 32];
    let rseed_randomness = [3u8; 32];
    let amount = 1000u64;
    let asset_id64 = 1u64;
    let address_index_1 = 0u32;
    let address_index_2 = 1u32;

    let dest_debtor = address_from_seed(&seed_phrase_randomness_1, address_index_1);
    let dest_creditor = address_from_seed(&seed_phrase_randomness_2, address_index_2);

    let value_to_send = Value {
        amount: Amount::from(amount),
        asset_id: asset::Id(Fq::from(asset_id64)),
    };

    // Create input notes
    let input_note_1 = Note::from_parts(
        dest_debtor.clone(),
        dest_creditor.clone(),
        value_to_send,
        Rseed(rseed_randomness),
    ).expect("should be able to create note");
    let input_note_nullifier_1 = Nullifier::derive(&input_note_1);

    let input_note_2 = Note::from_parts(
        dest_creditor.clone(),
        dest_debtor.clone(),
        value_to_send,
        Rseed(rseed_randomness),
    ).expect("should be able to create note");
    let input_note_nullifier_2 = Nullifier::derive(&input_note_2);

    // Create output notes
    let setoff_amount = amount;
    let value_reduced = Value {
        amount: Amount::from(amount - setoff_amount),
        asset_id: asset::Id(Fq::from(asset_id64)),
    };
    
    let output_note_1 = Note::from_parts(
        dest_debtor.clone(),
        dest_creditor.clone(),
        value_reduced,
        Rseed(rseed_randomness),
    ).expect("should be able to create note");
    let output_note_commitment_1 = output_note_1.commit();
    
    let output_note_2 = Note::from_parts(
        dest_creditor,
        dest_debtor,
        value_reduced,
        Rseed(rseed_randomness),
    ).expect("should be able to create note");
    let output_note_commitment_2 = output_note_2.commit();

    // Create merkle tree
    let constants = SettlementProofConst::default();
    let leaves: Vec<[Fq; 1]> = vec![[input_note_1.commit().0], [input_note_2.commit().0]];
    let tree = Poseidon377MerkleTree::new(
        &constants.leaf_crh_params,
        &constants.two_to_one_crh_params,
        leaves.clone(),
    ).unwrap();

    // Get auth paths
    let input_auth_path_1 = tree.generate_proof(0).unwrap();
    let input_auth_path_2 = tree.generate_proof(1).unwrap();

    let public = SettlementProofPublic {
        output_notes_commitments: vec![output_note_commitment_1, output_note_commitment_2],
        nullifiers: vec![input_note_nullifier_1, input_note_nullifier_2],
        root: tree.root(),
    };
    
    let private = SettlementProofPrivate {
        output_notes: vec![output_note_1, output_note_2],
        input_notes: vec![input_note_1, input_note_2],
        setoff_amount: Amount::from(setoff_amount),
        input_notes_proofs: vec![input_auth_path_1, input_auth_path_2]
    };

    // Generate random blinding factors
    let r = Fq::rand(&mut OsRng);
    let s = Fq::rand(&mut OsRng);

    c.bench_function("settlement proving", |b| {
        b.iter(|| prove(r, s, public.clone(), private.clone()))
    });

    // Print constraint count
    let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);

    let circuit = SettlementCircuit::with_dummy_witness();
    circuit
        .generate_constraints(cs.clone())
        .expect("can generate constraints");
    cs.finalize();
    let num_constraints = cs.num_constraints();
    println!("Number of constraints: {}", num_constraints);
}

criterion_group!(benches, settlement_proving_time);
criterion_main!(benches);
