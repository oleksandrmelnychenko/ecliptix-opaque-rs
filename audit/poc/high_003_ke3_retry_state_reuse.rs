// Demonstrates: KE3 retry on the same responder state after a failed verification.
// Historical impact (pre-fix): state reuse after failed KE3 could be abused as a bypass/oracle vector.
//
// Expected result on fixed code: first attempt fails; second attempt on same state also fails.

use opaque_agent::{
    create_registration_request, finalize_registration, generate_ke1, generate_ke3, InitiatorState,
    Ke1Message, Ke3Message, OpaqueInitiator, RegistrationRecord, RegistrationRequest,
};
use opaque_core::protocol;
use opaque_core::types::{KE1_LENGTH, KE2_LENGTH, KE3_LENGTH, REGISTRATION_RECORD_LENGTH};
use opaque_relay::{
    build_credentials, create_registration_response, generate_ke2, responder_finish, Ke2Message,
    OpaqueResponder, RegistrationResponse, ResponderCredentials, ResponderState,
};

const ACCOUNT_ID: &[u8] = b"alice@example.com";
const PASSWORD: &[u8] = b"correct horse battery staple";

fn register(responder: &OpaqueResponder) -> Vec<u8> {
    let initiator = OpaqueInitiator::new(responder.public_key()).unwrap();
    let mut state = InitiatorState::new();
    let mut req = RegistrationRequest::new();
    create_registration_request(PASSWORD, &mut req, &mut state).unwrap();

    let mut resp = RegistrationResponse::new();
    create_registration_response(responder, &req.data, ACCOUNT_ID, &mut resp).unwrap();

    let mut record = RegistrationRecord::new();
    finalize_registration(&initiator, &resp.data, &mut state, &mut record).unwrap();

    let mut out = vec![0u8; REGISTRATION_RECORD_LENGTH];
    protocol::write_registration_record(&record.envelope, &record.initiator_public_key, &mut out)
        .unwrap();
    out
}

fn main() {
    let responder = OpaqueResponder::generate().unwrap();
    let record = register(&responder);
    let initiator = OpaqueInitiator::new(responder.public_key()).unwrap();

    let mut client_state = InitiatorState::new();
    let mut ke1 = Ke1Message::new();
    generate_ke1(PASSWORD, &mut ke1, &mut client_state).unwrap();

    let mut ke1_bytes = vec![0u8; KE1_LENGTH];
    protocol::write_ke1(
        &ke1.credential_request,
        &ke1.initiator_public_key,
        &ke1.initiator_nonce,
        &ke1.pq_ephemeral_public_key,
        &mut ke1_bytes,
    )
    .unwrap();

    let mut creds = ResponderCredentials::new();
    build_credentials(&record, &mut creds).unwrap();

    let mut server_state = ResponderState::new();
    let mut ke2 = Ke2Message::new();
    generate_ke2(
        &responder,
        &ke1_bytes,
        ACCOUNT_ID,
        &creds,
        &mut ke2,
        &mut server_state,
    )
    .unwrap();

    let mut ke2_bytes = vec![0u8; KE2_LENGTH];
    protocol::write_ke2(
        &ke2.responder_nonce,
        &ke2.responder_public_key,
        &ke2.credential_response,
        &ke2.responder_mac,
        &ke2.kem_ciphertext,
        &mut ke2_bytes,
    )
    .unwrap();

    let mut ke3 = Ke3Message::new();
    generate_ke3(&initiator, &ke2_bytes, &mut client_state, &mut ke3).unwrap();

    let mut tampered_ke3 = [0u8; KE3_LENGTH];
    protocol::write_ke3(&ke3.initiator_mac, &mut tampered_ke3).unwrap();
    tampered_ke3[0] ^= 0xFF;

    let mut sk = Vec::new();
    let mut mk = Vec::new();
    let first = responder_finish(&tampered_ke3, &mut server_state, &mut sk, &mut mk);
    assert!(first.is_err(), "first KE3 verification must fail");

    let zero_ke3 = [0u8; KE3_LENGTH];
    let second = responder_finish(&zero_ke3, &mut server_state, &mut sk, &mut mk);
    assert!(
        second.is_err(),
        "fixed implementation must reject repeated KE3 on terminal state"
    );

    println!("State-reuse retry blocked: first={first:?}, second={second:?}");
}
