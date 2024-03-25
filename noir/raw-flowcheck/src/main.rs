mod merkle;
use merkle::*;

use light_poseidon::{Poseidon, PoseidonHasher};
use ark_bn254::{Fr};

// For printing
fn to_uint(x:&Fr) -> num_bigint::BigUint {
    (*x).into()
}

const V : usize = 16;
const E : usize = 32;

fn main() {

    let mut poseidon = Poseidon::<Fr>::new_circom(4).unwrap();

    // From gen_cycle.py
    let edges : [[usize;3];E] = [[13, 10, 76], [10, 5, 76], [5, 13, 76], [7, 6, 58], [6, 7, 58], [5, 8, 31], [8, 1, 31], [1, 5, 81], [1, 6, 74], [6, 4, 74], [4, 1, 74], [5, 4, 50], [4, 2, 111], [2, 0, 50], [0, 1, 50], [5, 14, 8], [14, 15, 8], [15, 11, 8], [11, 5, 8], [3, 9, 63], [9, 14, 63], [14, 3, 63], [2, 3, 61], [3, 8, 61], [8, 2, 61], [0, 2, 90], [2, 5, 90], [5, 1, 90], [1, 0, 90], [2, 4, 61], [0, 1, 0], [0, 1, 0]];


    // Initialize the all zeros merkle tree
    let mut acc_tree = compute_merkle_tree(&[Fr::from(0); V]);

    // Given a list of edges, produce all the proof witnesses
    let mut branches = Vec::new();
    for (i,[src,dst,amt]) in edges.iter().enumerate() {
	println!("{:?}", (i, src, dst, amt));

	println!("{:?}", acc_tree[0].iter());

	// Select the src and dst
	let path_s = compute_merkle_path(&acc_tree, *src);
	let path_d = compute_merkle_path(&acc_tree, *dst);

	// We should resolve this case or deal with the special case!
	assert!(*src != *dst);

	// Modify the amounts
	let net_s = acc_tree[0][*src] - Fr::from(*amt as u128);
	let net_d = acc_tree[0][*dst] + Fr::from(*amt as u128);
	
	// Update the tree
	let r1 = update_merkle_tree(&mut acc_tree, *src, net_s);
	let r2 = update_merkle_tree(&mut acc_tree, *dst, net_d);

	// Return the paths
	branches.push((path_s, path_d));
    }


    /*
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
     */
}
