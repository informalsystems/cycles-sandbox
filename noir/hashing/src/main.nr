use dep::std::hash::poseidon2::Poseidon2;
use dep::std::hash::poseidon;
use dep::std::hash::{pedersen_hash,mimc::mimc_bn254};


global N = 3000;

fn main(x: u64) -> pub (Field) {

    let mut arr = [0; N];
    // Use an input dependent access
    arr[x] = 1;

    // Compute the hash of an N array
    //let xHash = poseidon::bn254::hash_4(arr);
    let xHash = Poseidon2::hash(arr.map(|xi:u64| xi as Field), N);
    //let xHash = pedersen_hash(arr.map(|xi:u64| xi as Field));
    //let xHash = mimc_bn254(arr.map(|xi:u64| xi as Field));
    xHash
}

#[test]
fn test_main() {
    let xHash = main(0);
    assert(xHash != 0);
}
