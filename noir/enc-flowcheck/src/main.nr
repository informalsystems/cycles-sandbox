use dep::std::hash::poseidon2::Poseidon2;

use dep::std::ec::tecurve::affine::{Point,Curve};
use dep::std::ec::consts::te::{baby_jubjub};


// Graph parameters are statically fixed
global V = 10; // how many nodes
global E = 4; // how many edges

global SIZE = 1;

// this will be encrypted into 3 field elements:
//  2 for Point
//  1 for src | dst | amt
struct Edge {
    srcPubKey: Point,
    src: u32,
    dst: u32,
    amt: i64 // Signed 128-bit integer amt
}

unconstrained fn find(obligations: [Edge; E], src: u32, dst: u32) -> i64 {
    let mut found_index = -1;

    for i in 0..obligations.len() { 
        let e = obligations[i];
        if (e.src == src) && (e.dst == dst) {
            found_index = i as i64;
        }
    }

    if found_index < 0 {
        assert(false);
    }
    found_index
}

unconstrained fn hashField(r: Field) -> Field {
    Poseidon2::hash([r], 1)
}

unconstrained fn unpackValue(valueField: Field) -> (u32, u32, i64){
    // packed:
    // let value = flow.src + flow.dst << 32 + flow.amt << 64;
    
    let value = valueField as u128;
    
    let mask = ((1 << 32) - 1);
    let src = value & mask;
    let dst = (value >> 32) & mask;
    let amt = (value >> 64) & mask;

    (src, dst, amt)
}

// takes in 
//  - enclaves private key
//  - encrypted obligations (from the chain) 
//  - clear text flow solution (from the solver)
//
// do:
//  - decrypt
//  - checks (flows dont exceed obs, flows balance)
//  - encrypt
//
// we need to check:
//  - flows do not exceed obligations. this implies that each flow corresponds to an obligation
//  - flows balance
//
fn main(
    enclavePrivKey: Field, 
    cipherObligations: pub [(Point, [Field;3]); E], 
    flows: [Edge; E], // TODO separate param
    randomSeed: Field,
) -> pub [(Point, [Field;1]); 2*E]{


    //------------------
    // Decrypt and get pubkeys
    // ----------------

    // array of public keys fetched from decrypted Edges
    let mut keys = [Point{x:0, y:0}; V];

    // array of clear text edges from decrypting cipherObligations.
    // this allows 
    let mut edges = [Edge{srcPubKey: Point{x:0,y:0},src:0,dst:0,amt:0}; E];

    // Loop over encrypted edges to get clear text edges and src pubkeys
    for i in 0..cipherObligations.len() { 
        let cipherEdge = cipherObligations[i];

        let e = decrypt(enclavePrivKey, cipherEdge);
        let x,y,packedValue = e[0], e[1], e[2];
        let (src, dst, amt) = unpackValue(packedValue); 

        let srcPubKey = Point{x:x,y:y};

        keys[e.src] = srcPubKey; // TODO deal with duplicate srcs
        
        edges[i] = Edge{srcPubKey: srcPubKey, src: src, dst: dst, amt: amt};
    }


    //------------------
    // Run Checks
    // ----------------


    // Local RAM array for accumulating net position
    let mut net = [0; V];

    // Loop over flows to accumulate net positions 
    // and check that the flow is within the obligation amount
    for i in 0..flows.len() { 
        let f  = flows[i];

	// Input-dependent lookup
	net[f.src] -= f.amt;
	net[f.dst] += f.amt;

        let edgeID = find(edges, f.src, f.dst);

        // assert flow is less than obligation
        let obligationAmt = edges[edgeID].amt;
        let flowAmt = f.amt;
        assert(flowAmt <= obligationAmt);
    }

    // heck the final net flow is zero
    for n in net {
	assert(n == 0);
    }    

    //------------------
    // Encrypt Setoffs
    // ----------------

    // encrypted set off notices, 
    // 2 for each edge, with 1 encrypted to each of src and dst
    // Field is (src | dst | amt)
    let mut setoffs = [(Point{0,0}, [0 as Field; 1]); 2*E];
// ) -> pub [(Point, [Field;1]); 2*E]{

    let mut r = randomSeed;

    for i in 0..flows.len(){
        let flow = flows[i];

        // encode the flow value as src | dst | amt)
        let value = (flow.src as u128) + (flow.dst as u128) << 32 + (flow.amt as u128) << 64;

        // encrypt to src
        let srcKey = keys[flow.src];
        r = hashField(r);
        setoffs[2*i] = encrypt(srcKey, r, [value]);

        // encrypt to dst
        let dstKey = keys[flow.dst];
        r = hashField(r);
        setoffs[2*i+1] = encrypt(dstKey, r, [value]);
    }

    // return encrypted setoffs
    //setoffs
    [(Point{x:0,y:0}, [0 as Field; 1]); 2*E]
}

global bjj = baby_jubjub();
global G = bjj.base8;

// Compute the public key X = x*G
fn derive_pubkey(x: Field) -> (Point) {
    let X = bjj.curve.mul(x, G);
    X
}

// encrypt msg of size 32 bytes using pubkey and randomness r
fn encrypt(pubkey: Point, r: Field, msg: [Field; SIZE]) -> (Point, [Field; SIZE]) {
    // gA = pubkey
    let gR  = derive_pubkey(r);
    let gAR = bjj.curve.mul(r, pubkey);

    let mut cipherText = [0;SIZE];

    for i in 0..msg.len() {
        let m = msg[i];

        // hash(m || counter)
        let hashKey = Poseidon2::hash([gAR.x, i as Field], 2);

        cipherText[i] = m + hashKey;
    }

    (gR, cipherText)
}

fn decrypt(privkey: Field, cipher: (Point, [Field;SIZE])) -> [Field; SIZE] {

    let (gR, cipherText) = cipher;
    let gAR = bjj.curve.mul(privkey, gR);

    let mut clearText = [0;SIZE];

    for i in 0..cipherText.len() {
        let m = cipherText[i];

        // hash(m || counter)
        let hashKey = Poseidon2::hash([gAR.x, i as Field], 2);

        clearText[i] = m - hashKey;
    }

    clearText
}


#[test]
fn test_main() {
    let a = 0x3fbbccb240537392421955b07a0d65eded9e7637995bf2f9cfe29e19b580e4;
    let r = 0x106885ee5c8f2757c6bde259b31b3f00300f538c8901b28c5bcf982c85e17493;
    let mut msg = [0; SIZE];
    msg[0] = 42;
    msg[1] = 137; // alpha baby
    msg[2] = 118;

    let gA = derive_pubkey(a);
    println(gA);

    let (gR, cipherText) = encrypt(gA, r, msg);
    let clearText = decrypt(a, (gR, cipherText));

    assert(msg == clearText);
}


/*#[test]
fn test_main() {
    let mut edges = [Edge{src:0,dst:1,amt:5},
		     Edge{src:1,dst:2,amt:5},
		     Edge{src:2,dst:0,amt:5},
		     Edge{src:2,dst:0,amt:0}];
    let _ = main(edges);
}*/

/*#[test(should_fail)]
fn test_fail() {
    let mut edges = [Edge{src:0,dst:1,amt:5},
		     Edge{src:1,dst:2,amt:5},
		     Edge{src:2,dst:0,amt:5},
		     Edge{src:2,dst:0,amt:0}];
    edges[0].amt += 1;
    let _ = main(edges);
}
*/
