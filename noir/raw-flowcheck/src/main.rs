mod merkle;
use merkle::*;

use ark_bn254::{Fr};

// For printing
fn to_uint(x:&Fr) -> num_bigint::BigUint {
    (*x).into()
}

fn main() {

    // Compute the root
    let arr = (0..16).map(Fr::from).collect::<Vec<Fr>>();
    let hash = compute_merkle_root2(&arr);
    println!("root hash {:?}", to_uint(&hash));

    // Compute the whole tree
    let mut tree = compute_merkle_tree(&arr);
    assert!(hash == tree.last().unwrap()[0]);

    // Select a path
    let path = compute_merkle_path(&tree, 2);

    // Verify the path
    let root2 = compute_merkle_root(Fr::from(2), 2, &path);
    assert!(hash == root2);

    // Update the path
    let root3 = update_merkle_tree(&mut tree, 3, Fr::from(42));
    assert!(root3 != root2);

    // Recompute after updating
    let path = compute_merkle_path(&tree, 3);
    let root4 = compute_merkle_root(Fr::from(42), 3, &path);
    assert!(root3 == root4);
}
