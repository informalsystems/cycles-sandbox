#![no_std]

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SimpleSetOff {
    pub id: Option<usize>,
    pub debtor: u32,
    pub creditor: u32,
    pub amount: i64,
    pub set_off: i64,
    pub remainder: i64,
}
