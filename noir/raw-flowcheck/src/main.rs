mod merkle;
use merkle::*;

use light_poseidon::{Poseidon, PoseidonHasher};
use ark_bn254::{Fr};

// For printing
fn to_uint(x:&Fr) -> num_bigint::BigUint {
    (*x).into()
}

const V : usize = 64;
const E : usize = 128;

// From gen_cycle.py
//const edges : [[usize;3];E] = include!("../50kcycle.rsi");
const edges : [[usize;3];E] = [[30, 24, 49], [24, 20, 49], [20, 40, 49], [40, 30, 49], [58, 8, 89], [8, 35, 89], [35, 58, 89], [34, 18, 9], [18, 28, 9], [28, 38, 9], [38, 34, 9], [14, 56, 31], [56, 32, 31], [32, 23, 31], [23, 14, 31], [13, 53, 85], [53, 25, 85], [25, 58, 85], [58, 34, 85], [34, 13, 85], [55, 24, 11], [24, 11, 11], [11, 38, 11], [38, 29, 11], [29, 55, 11], [26, 36, 98], [36, 45, 98], [45, 5, 98], [5, 26, 98], [55, 58, 39], [58, 55, 39], [14, 18, 81], [18, 41, 81], [41, 11, 81], [11, 14, 81], [17, 39, 73], [39, 40, 73], [40, 31, 73], [31, 1, 73], [1, 17, 73], [4, 63, 48], [63, 4, 48], [18, 39, 29], [39, 5, 29], [5, 0, 29], [0, 18, 29], [10, 50, 30], [50, 3, 30], [3, 10, 30], [43, 60, 88], [60, 23, 88], [23, 43, 88], [14, 63, 48], [63, 39, 48], [39, 14, 48], [0, 37, 46], [37, 11, 46], [11, 9, 46], [9, 0, 46], [44, 51, 44], [51, 44, 44], [15, 0, 59], [0, 46, 59], [46, 3, 59], [3, 6, 59], [6, 15, 59], [55, 7, 33], [7, 56, 33], [56, 39, 33], [39, 55, 33], [41, 30, 84], [30, 37, 84], [37, 17, 84], [17, 41, 84], [26, 15, 10], [15, 21, 10], [21, 25, 97], [25, 26, 10], [32, 33, 13], [33, 32, 13], [8, 50, 83], [50, 55, 83], [55, 15, 83], [15, 8, 83], [1, 5, 9], [5, 59, 9], [59, 1, 9], [56, 60, 7], [60, 10, 7], [10, 4, 7], [4, 11, 7], [11, 56, 7], [14, 38, 87], [38, 21, 87], [25, 14, 87], [43, 38, 36], [38, 43, 36], [47, 11, 38], [11, 57, 38], [57, 47, 38], [26, 13, 35], [13, 8, 35], [8, 45, 35], [45, 11, 35], [11, 26, 35], [22, 17, 66], [17, 22, 66], [21, 62, 24], [62, 21, 24], [16, 20, 25], [20, 35, 25], [35, 46, 25], [46, 16, 25], [33, 2, 3], [2, 43, 3], [43, 57, 3], [57, 7, 3], [7, 33, 3], [43, 37, 89], [37, 47, 89], [47, 43, 89], [0, 0, 0], [0, 0, 0], [0, 0, 0], [0, 0, 0], [0, 0, 0], [0, 0, 0], [0, 0, 0]];


fn main() {

    let mut poseidon = Poseidon::<Fr>::new_circom(4).unwrap();

    // Initialize the all zeros merkle tree
    let mut acc_tree = compute_merkle_tree(&[Fr::from(0); V]);

    // Given a list of edges, produce all the proof witnesses
    let mut branches = Vec::new();
    for (i,[src,dst,amt]) in edges.iter().enumerate() { 
	println!("{:?}", acc_tree[0].iter().map(|x| to_uint(x).to_str_radix(10)).collect::<Vec<_>>());

	if i % 1 == 0 {
	    println!("{:?}", (i, src, dst, amt));
	}	

	// Select the src and dst
	let path_s = compute_merkle_path(&acc_tree, *src);
	let path_d = compute_merkle_path(&acc_tree, *dst);

	// We should resolve this case or deal with the special case!
	//assert!(*src != *dst);

	// Modify the amounts
	let net_s = acc_tree[0][*src] - Fr::from(*amt as u128);
	let net_d = acc_tree[0][*dst] + Fr::from(*amt as u128);
	
	// Update the tree
	let r1 = update_merkle_tree(&mut acc_tree, *src, net_s);
	let r2 = update_merkle_tree(&mut acc_tree, *dst, net_d);

	// Return the paths
	branches.push((path_s, path_d));
    }

    println!("Branches: {:?}", branches);

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
