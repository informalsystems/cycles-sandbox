use dep::std::hash::poseidon;
use dep::std::hash::poseidon2::Poseidon2;

// Graph parameters are statically fixed
global V2 = 16;
global V = 1<<V2; // how many nodes
global E = 262144; // how many edges

global C = 10; // edges to process in one go

struct Edge {
    src: u32,
    dst: u32,
    amt: i64 // Signed 128-bit integer amt
}

fn compute_merkle_root(leaf: Field, index: Field, hash_path: [Field;V2]) -> Field {
    let n = hash_path.len();
    let mut current_index = index;
    let mut current = leaf;
    for i in 0..n {
        let path_bit = current_index as u64 % 2 != 0;
        let (hash_left, hash_right) = if path_bit {
            (hash_path[i], current)
        } else {
            (current, hash_path[i])
        };
        //current = poseidon::bn254::hash_2([hash_left, hash_right]);
	current = Poseidon2::hash([hash_left, hash_right], 2);
        current_index /= 2; // Move up to the next layer
    }
    current
}


// Iterate over each edge, accumulating the net balance
fn main(start_root : pub Field,
	edges: [Edge; C],
	branches : [[Field;16]; C]) -> pub Field {

    // Check start_root
    let cur_root = start_root;
    
    // Loop over edges to accumulate net position
    for i in 0..edges.len() {
	let e = edges[i];
	assert(compute_merkle_root(0, e.src as Field, branches[i]) == start_root);
	
	// Input-dependent lookup
	//net[e.src] -= e.amt;
	//net[e.dst] += e.amt;

	// cur_root := 
    }

    let vHash = cur_root;
    vHash
}
/*
#[test]
fn test_main() {
    let mut edges = [Edge{src:0,dst:1,amt:5},
		     Edge{src:1,dst:2,amt:5},
		     Edge{src:2,dst:0,amt:5},
		     Edge{src:2,dst:0,amt:0}];
    main(edges);
}

#[test(should_fail)]
fn test_fail() {
    let mut edges = [Edge{src:0,dst:1,amt:5},
		     Edge{src:1,dst:2,amt:5},
		     Edge{src:2,dst:0,amt:5},
		     Edge{src:2,dst:0,amt:0}];
    edges[0].amt += 1;
    main(edges);
}
*/
