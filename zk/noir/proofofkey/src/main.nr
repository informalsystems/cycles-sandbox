use dep::std::ec::tecurve::affine::{Point,Curve};
use dep::std::ec::consts::te::{baby_jubjub};

global bjj = baby_jubjub();
global G = bjj.base8;

fn derive_pubkey(x: Field) -> (Point) {
    // Compute the public key X = x*G
    let X = bjj.curve.mul(x, G);
    X
}

fn prove_knowledge_of_key(x: Field, X: Point) {
    assert(derive_pubkey(x) == X);
}


fn main(x : Field, X_x : pub Field, X_y : pub Field) {
    println(x);
    println(derive_pubkey(x));
    prove_knowledge_of_key(x, Point { x: X_x, y: X_y });
}

#[test]
fn test_main() {
    let x = 0x3fbbccb240537392421955b07a0d65eded9e7637995bf2f9cfe29e19b580e4;
    let X = Point {
	x: 0x23bc14fd02ca79df174c4f33f20f9fc099d95cdd29b1a248beb4959ae893c607,
	y: 0x106885ee5c8f2757c6bde259b31b3f00300f538c8901b28c5bcf982c85e17493 };
    main(x, X.x, X.y);

    // Perturb the values to make test fail
}
