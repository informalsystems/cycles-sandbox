use dep::std::hash::poseidon2::Poseidon2;

// Graph parameters are statically fixed
global V = 4000; // how many nodes
global E = 3; // how many edges

struct Edge {
    src: u32,
    dst: u32,
    amt: i64 // Signed 128-bit integer amt
}

// Iterate over each edge, accumulating the net balance
fn main(edges: [Edge; E]) -> pub Field {

    // Local RAM array for accumulating net position
    let mut net = [0; V];

    // Loop over edges to accumulate net position
    for e in edges {
	// Input-dependent lookup
	net[e.src] -= e.amt;
	net[e.dst] += e.amt;
    }

    // Finally check the final net flow is zero
    for n in net {
	assert(n == 0);
    }

    // Accumulate residual graph into a Merkle tree
    // TODO: subtract the residual graph...
    let vHash = Poseidon2::hash(net.map(|n:i64| n as Field), V);
    vHash
}

#[test]
fn test_main() {
    let mut edges = [Edge{src:0,dst:1,amt:5},
		     Edge{src:1,dst:2,amt:5},
		     Edge{src:2,dst:0,amt:5}];
    main(edges);
}

#[test(should_fail)]
fn test_fail() {
    let mut edges = [Edge{src:0,dst:1,amt:5},
		     Edge{src:1,dst:2,amt:5},
		     Edge{src:2,dst:0,amt:5}];
    edges[0].amt += 1;
    main(edges);
}
