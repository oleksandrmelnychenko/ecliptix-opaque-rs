// Demonstrates: account enumeration oracle from distinct server behavior.
// Impact: attacker can distinguish "account exists" from "account missing" before password verification.
//
// Signal:
// - Existing account: server returns KE2 (authentication continues)
// - Missing account: server returns InvalidPublicKey / InvalidEnvelope immediately

use opaque_agent::{create_registration_request, generate_ke1, finalize_registration, InitiatorState, Ke1Message, OpaqueInitiator, RegistrationRecord, RegistrationRequest};
use opaque_core::protocol;
use opaque_core::types::{KE1_LENGTH, OpaqueError, REGISTRATION_RECORD_LENGTH};
use opaque_relay::{build_credentials, create_registration_response, generate_ke2, Ke2Message, OpaqueResponder, RegistrationResponse, ResponderCredentials, ResponderState};

const ACCOUNT_ID: &[u8] = b"alice@example.com";
const REAL_PASSWORD: &[u8] = b"correct horse battery staple";
const WRONG_PASSWORD: &[u8] = b"not-the-password";

fn register_account(responder: &OpaqueResponder) -> Vec<u8> {
    let initiator = OpaqueInitiator::new(responder.public_key()).unwrap();
    let mut state = InitiatorState::new();
    let mut req = RegistrationRequest::new();
    create_registration_request(REAL_PASSWORD, &mut req, &mut state).unwrap();

    let mut resp = RegistrationResponse::new();
    create_registration_response(responder, &req.data, ACCOUNT_ID, &mut resp).unwrap();

    let mut record = RegistrationRecord::new();
    finalize_registration(&initiator, &resp.data, &mut state, &mut record).unwrap();

    let mut out = vec![0u8; REGISTRATION_RECORD_LENGTH];
    protocol::write_registration_record(&record.envelope, &record.initiator_public_key, &mut out).unwrap();
    out
}

fn main() {
    let responder = OpaqueResponder::generate().unwrap();
    let record = register_account(&responder);

    // Attacker starts login with wrong password.
    let mut client_state = InitiatorState::new();
    let mut ke1 = Ke1Message::new();
    generate_ke1(WRONG_PASSWORD, &mut ke1, &mut client_state).unwrap();
    let mut ke1_bytes = vec![0u8; KE1_LENGTH];
    protocol::write_ke1(
        &ke1.credential_request,
        &ke1.initiator_public_key,
        &ke1.initiator_nonce,
        &ke1.pq_ephemeral_public_key,
        &mut ke1_bytes,
    )
    .unwrap();

    // Case A: existing account -> server proceeds and emits KE2.
    let mut existing_creds = ResponderCredentials::new();
    build_credentials(&record, &mut existing_creds).unwrap();

    let mut state_existing = ResponderState::new();
    let mut ke2_existing = Ke2Message::new();
    let existing_result = generate_ke2(
        &responder,
        &ke1_bytes,
        ACCOUNT_ID,
        &existing_creds,
        &mut ke2_existing,
        &mut state_existing,
    );
    assert!(existing_result.is_ok(), "existing account should progress to KE2");

    // Case B: missing account -> immediate, distinguishable error.
    let missing_creds = ResponderCredentials::new(); // registered=false, zero key material
    let mut state_missing = ResponderState::new();
    let mut ke2_missing = Ke2Message::new();
    let missing_result = generate_ke2(
        &responder,
        &ke1_bytes,
        b"unknown@example.com",
        &missing_creds,
        &mut ke2_missing,
        &mut state_missing,
    );

    assert!(
        matches!(missing_result, Err(OpaqueError::InvalidPublicKey) | Err(OpaqueError::InvalidEnvelope)),
        "missing-account path emits a different error than wrong password"
    );

    println!("Enumeration oracle confirmed:");
    println!("  existing account => KE2 returned");
    println!("  missing account  => {:?}", missing_result);
}

