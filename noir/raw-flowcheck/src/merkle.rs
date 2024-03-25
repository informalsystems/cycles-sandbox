use light_poseidon::{Poseidon, PoseidonHasher};
use ark_bn254::{Fr};

// Compute a merkle tree given an array
// This function now returns a Vec<Vec<Fr>>, with each inner Vec<Fr> being a layer in the Merkle tree.
pub fn compute_merkle_tree(arr: &[Fr]) -> Vec<Vec<Fr>> {
    assert!(arr.len().next_power_of_two() == arr.len());
    
    let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();
    if arr.is_empty() {
        unimplemented!() // Not defined for empty arrays
    } else if arr.len() == 1 {
        return vec![vec![arr[0].clone()]];
    }

    let mid = arr.len() / 2;
    let left_tree = compute_merkle_tree(&arr[0..mid]);
    let right_tree = compute_merkle_tree(&arr[mid..]);
    assert!(left_tree.len() == right_tree.len());

    // Combine the left and right trees at each level and add a new root level.
    let mut combined_tree = Vec::new();
    let max_depth = left_tree.len();
    for depth in 0..max_depth {
        let mut layer = Vec::new();
        layer.extend_from_slice(&left_tree[depth]);
        layer.extend(right_tree[depth].iter().cloned());
        combined_tree.push(layer);
    }

    // Compute and add the new root from the last elements of the left and right trees.
    let new_root = poseidon.hash(&[
	*combined_tree.last().unwrap().first().unwrap(),
	*combined_tree.last().unwrap(). last().unwrap()
    ]).unwrap();
    combined_tree.push(vec![new_root]);

    combined_tree
}

// Compute just the root
pub fn compute_merkle_root2(arr: &[Fr]) -> Fr {
    assert!(arr.len().next_power_of_two() == arr.len());    
    let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();
    match arr.len() {
        0 => unimplemented!(),
        1 => arr[0],
        _ => {
            let mid = arr.len() / 2;
            let left  = compute_merkle_root2(&arr[0..mid]);
            let right = compute_merkle_root2(&arr[mid..]);
            poseidon.hash(&[left, right]).unwrap()
        }
    }
}

// Compute the path
pub fn compute_merkle_path(tree: &Vec<Vec<Fr>>, leaf_index: usize) -> Vec<Fr> {
    let mut path = Vec::new();
    let mut current_index = leaf_index;
    for layer in tree.iter().take(tree.len() - 1) { // Exclude the root
        let pair_index = if current_index % 2 == 0 { current_index + 1 } else { current_index - 1 };
        path.push(layer[pair_index].clone());
        current_index /= 2; // Move up to the next layer
    }
    path
}

// Merkle proof
pub fn compute_merkle_root(leaf: Fr, index: usize, hash_path: &[Fr]) -> Fr {
    let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();
    let n = hash_path.len();
    let mut current_index = index;
    let mut current = leaf;
    for i in 0..n {
        let path_bit = current_index % 2 != 0;
        let (hash_left, hash_right) = if path_bit {
            (hash_path[i], current)
        } else {
            (current, hash_path[i])
        };
        current = poseidon.hash(&[hash_left, hash_right]).unwrap();
        current_index /= 2; // Move up to the next layer
    }
    current
}

// Update an element of the tree
pub fn update_merkle_tree(tree: &mut Vec<Vec<Fr>>, leaf_index: usize, new_value: Fr) -> Fr {
    let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();    
    // Step 1: Update the leaf node
    tree[0][leaf_index] = new_value;

    // Step 2: Update the path from the updated leaf to the root
    let mut current_index = leaf_index;
    for depth in 0..tree.len() - 1 { // Exclude the root itself
        let pair_index = if current_index % 2 == 0 { current_index + 1 } else { current_index - 1 };
        
        let parent_index = current_index / 2;
        let sibling = &tree[depth][pair_index];	
        let new_parent = if current_index % 2 == 0 {
            poseidon.hash(&[tree[depth][current_index], *sibling]).unwrap()
        } else {
            poseidon.hash(&[*sibling, tree[depth][current_index]]).unwrap()
        };

        // Update the parent node in the next layer
        tree[depth + 1][parent_index] = new_parent;
        current_index = parent_index;
    }
    tree.last().unwrap()[0]
}


#[cfg(test)]
#[test]
fn merkle_test() {
    // Compute the root
    let arr = (0..16).map(Fr::from).collect::<Vec<Fr>>();
    let hash = compute_merkle_root2(&arr);
    
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
