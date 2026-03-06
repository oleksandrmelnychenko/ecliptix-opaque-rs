// Demonstrates: identity-point injection in OPRF request path is rejected.
// Historical impact (pre-fix): active MITM could replace blinded OPRF element with identity,
// weakening OPRF contribution during registration and enabling downgrade-style abuse.
//
// Expected result on fixed code: registration response creation fails.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::traits::Identity;
use opaque_relay::{create_registration_response, OpaqueResponder, RegistrationResponse, ResponderKeyPair};

const ACCOUNT_ID: &[u8] = b"alice@example.com";

fn main() {
    let keypair = ResponderKeyPair::generate().unwrap();
    let responder = OpaqueResponder::new(keypair, [7u8; 32]).unwrap();

    // Attacker-crafted identity element instead of a valid blinded OPRF point.
    let identity = RistrettoPoint::identity().compress().to_bytes();
    let mut response = RegistrationResponse::new();

    let result = create_registration_response(&responder, &identity, ACCOUNT_ID, &mut response);
    assert!(
        result.is_err(),
        "fixed implementation must reject identity-point OPRF requests"
    );

    println!("Identity-point injection blocked: {:?}", result);
}
