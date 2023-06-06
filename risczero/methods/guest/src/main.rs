#![no_main]
// If you want to try std support, also update the guest Cargo.toml file
#![no_std] // std support is experimental

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::ops::Neg;

use mtcs_core::SimpleSetOff;
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);
pub fn main() {
    let set_offs: Vec<SimpleSetOff> = env::read();
    check(&set_offs);
}

fn check(setoffs: &[SimpleSetOff]) {
    fn assert_eq_pos_neg(b: &BTreeMap<u32, i64>) {
        let pos_b: i64 = b.values().cloned().filter(|amount| amount > &0).sum();

        let neg_b = b
            .values()
            .cloned()
            .filter(|amount| amount < &0)
            .sum::<i64>()
            .neg();

        assert_eq!(pos_b, neg_b);
    }

    // ba - net balance positions of the obligation network
    let ba = setoffs.iter().fold(BTreeMap::<_, _>::new(), |mut acc, so| {
        *acc.entry(so.creditor).or_default() += so.amount;
        *acc.entry(so.debtor).or_default() -= so.amount;
        acc
    });

    // bl - net balance positions of the remaining acyclic network
    let bl = setoffs.iter().fold(BTreeMap::<_, _>::new(), |mut acc, so| {
        *acc.entry(so.creditor).or_default() += so.remainder;
        *acc.entry(so.debtor).or_default() -= so.remainder;
        acc
    });

    // bc - net balance positions of the cyclic network
    let bc = setoffs.iter().fold(BTreeMap::<_, _>::new(), |mut acc, so| {
        *acc.entry(so.creditor).or_default() += so.set_off;
        *acc.entry(so.debtor).or_default() -= so.set_off;
        acc
    });

    // SUM(+NID) == SUM(-NID) for all b-vectors
    assert_eq_pos_neg(&ba);
    assert_eq_pos_neg(&bc);
    assert_eq_pos_neg(&bl);

    // ba == bl
    assert!(ba.iter().all(|(firm, amount)| amount == &bl[firm]));

    // set-off consistency check
    // (i.e. the sum of all set-off amounts where Alice is a debtor equals the sum of all set-off amounts where Alice is a creditor)
    let debtors = setoffs
        .iter()
        .fold(BTreeMap::<_, i64>::new(), |mut acc, so| {
            *acc.entry(so.debtor).or_default() += so.set_off;
            acc
        });
    let creditors = setoffs
        .iter()
        .fold(BTreeMap::<_, i64>::new(), |mut acc, so| {
            *acc.entry(so.creditor).or_default() += so.set_off;
            acc
        });
    assert!(creditors
        .iter()
        .filter(|(_, amount)| amount > &&0)
        .all(|(firm, amount)| amount == &debtors[firm]));
    assert!(debtors
        .iter()
        .filter(|(_, amount)| amount > &&0)
        .all(|(firm, amount)| amount == &creditors[firm]));

    // let ba_len = ba.len();
    let nid_a: i64 = ba.into_values().filter(|amount| amount > &0).sum();
    // let nid_c: i64 = bc.into_values().filter(|amount| amount > &0).sum();
    let nid_l: i64 = bl.into_values().filter(|amount| amount > &0).sum();

    // NID before and after algo run must be the same
    assert_eq!(nid_a, nid_l);

    // let debt_before = setoffs.iter().map(|s| s.amount).sum();
    // let debt_after = setoffs.iter().map(|s| s.remainder).sum();
    // let compensated = setoffs.iter().map(|s| s.set_off).sum();
}
