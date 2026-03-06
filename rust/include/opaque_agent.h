#pragma once
#include "opaque_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Agent (client-side) API — Ecliptix OPAQUE
 *
 * All operations here involve private key material and run entirely on the
 * client device. The relay never calls these functions.
 *
 * OWNERSHIP RULES (apply to every function in this file):
 *   - Parameters named `out_handle` write a newly allocated opaque handle.
 *     The caller owns the handle and MUST destroy it with the matching
 *     _destroy() function when done.
 *   - Parameters named `out_error` receive an optional error detail struct.
 *     If non-NULL and an error occurs the struct is populated; free it with
 *     opaque_error_free() after use.  Pass NULL to ignore error details.
 *   - All byte-slice inputs (`const uint8_t* foo, size_t foo_length`) are
 *     borrowed for the duration of the call only; the caller retains ownership.
 *   - A handle MAY NOT be used concurrently. A second call on the same handle
 *     while the first is still running returns OPAQUE_ERROR_BUSY.
 *
 * ERROR HANDLING:
 *   Every fallible function returns OpaqueErrorCode. Check for OPAQUE_SUCCESS
 *   (0) before reading any output buffer — values are undefined on failure.
 */

/* ── Handle management ────────────────────────────────────────────────────── */

/**
 * Creates a new agent handle bound to a specific relay's public key.
 *
 * @param relay_public_key  32-byte Ristretto255 compressed relay public key.
 * @param key_length        Must be exactly OPAQUE_PUBLIC_KEY_LENGTH (32).
 * @param out_handle        Receives the new handle (caller must destroy).
 * @param out_error         Optional; populated on failure.
 * @return OPAQUE_SUCCESS or an error code.
 */
OPAQUE_API OpaqueErrorCode opaque_agent_create(
    const uint8_t*       relay_public_key,
    size_t               key_length,
    OpaqueAgentHandle**  out_handle,
    OpaqueError*         out_error);

/**
 * Destroys an agent handle, securely zeroizing all key material.
 *
 * Sets *handle_ptr to NULL. Calling on an already-NULL pointer is a safe no-op.
 */
OPAQUE_API void opaque_agent_destroy(OpaqueAgentHandle** handle_ptr);

/**
 * Allocates a fresh per-flow state for one registration or authentication attempt.
 *
 * The state has a 5-minute lifetime. After expiry, subsequent calls return
 * OPAQUE_ERROR_VALIDATION. A single state MUST NOT be reused across flows.
 *
 * @param out_handle  Receives the new state handle (caller must destroy).
 * @param out_error   Optional; populated on failure.
 * @return OPAQUE_SUCCESS or an error code.
 */
OPAQUE_API OpaqueErrorCode opaque_agent_state_create(
    OpaqueAgentStateHandle**  out_handle,
    OpaqueError*              out_error);

/**
 * Destroys a per-flow state, securely zeroizing all cryptographic material.
 *
 * Sets *handle_ptr to NULL. Safe to call on a NULL pointer.
 */
OPAQUE_API void opaque_agent_state_destroy(OpaqueAgentStateHandle** handle_ptr);

/* ── Registration ─────────────────────────────────────────────────────────── */

/**
 * Registration step 1/2. Produces a 33-byte OPRF-blinded registration request.
 *
 * Send the request bytes to the server; it replies with a 65-byte response.
 *
 * @param agent_handle    Handle from opaque_agent_create().
 * @param password        User's password (raw bytes; 1–4096 bytes).
 * @param password_length Length of password in bytes.
 * @param state_handle    Fresh state from opaque_agent_state_create().
 * @param request_out     Output buffer (must be >= OPAQUE_REGISTRATION_REQUEST_LENGTH bytes).
 * @param request_length  Size of request_out.
 * @param out_error       Optional; populated on failure.
 * @return OPAQUE_SUCCESS or an error code.
 */
OPAQUE_API OpaqueErrorCode opaque_agent_create_registration_request(
    OpaqueAgentHandle*      agent_handle,
    const uint8_t*          password,
    size_t                  password_length,
    OpaqueAgentStateHandle* state_handle,
    uint8_t*                request_out,
    size_t                  request_length,
    OpaqueError*            out_error);

/**
 * Registration step 2/2. Creates the encrypted registration record (169 bytes).
 *
 * Send the record to the server for permanent storage. The server cannot
 * decrypt the envelope inside.
 *
 * Returns OPAQUE_ERROR_AUTH_FAILED if the server's public key in the response
 * does not match the one provided at agent creation (MITM protection).
 *
 * @param agent_handle    Handle from opaque_agent_create().
 * @param response        Server's 65-byte registration response.
 * @param response_length Must be OPAQUE_REGISTRATION_RESPONSE_LENGTH (65).
 * @param state_handle    Same state used in step 1.
 * @param record_out      Output buffer (must be >= OPAQUE_REGISTRATION_RECORD_LENGTH bytes).
 * @param record_length   Size of record_out.
 * @param out_error       Optional; populated on failure.
 * @return OPAQUE_SUCCESS or an error code.
 */
OPAQUE_API OpaqueErrorCode opaque_agent_finalize_registration(
    OpaqueAgentHandle*      agent_handle,
    const uint8_t*          response,
    size_t                  response_length,
    OpaqueAgentStateHandle* state_handle,
    uint8_t*                record_out,
    size_t                  record_length,
    OpaqueError*            out_error);

/* ── Authentication ───────────────────────────────────────────────────────── */

/**
 * Authentication step 1/3. Produces the 1273-byte KE1 message.
 *
 * Send KE1 to the server along with the user's account identifier.
 * The server replies with a 1377-byte KE2 message.
 *
 * @param agent_handle    Handle from opaque_agent_create().
 * @param password        User's password (raw bytes; 1–4096 bytes).
 * @param password_length Length of password in bytes.
 * @param state_handle    Fresh state from opaque_agent_state_create().
 * @param ke1_out         Output buffer (must be >= OPAQUE_KE1_LENGTH bytes).
 * @param ke1_length      Size of ke1_out.
 * @param out_error       Optional; populated on failure.
 * @return OPAQUE_SUCCESS or an error code.
 */
OPAQUE_API OpaqueErrorCode opaque_agent_generate_ke1(
    OpaqueAgentHandle*      agent_handle,
    const uint8_t*          password,
    size_t                  password_length,
    OpaqueAgentStateHandle* state_handle,
    uint8_t*                ke1_out,
    size_t                  ke1_length,
    OpaqueError*            out_error);

/**
 * Authentication step 2/3. Processes the server's KE2 and produces the 65-byte KE3.
 *
 * This step performs mutual authentication. Returns OPAQUE_ERROR_AUTH_FAILED if
 * the password is wrong or the server's KE2 is tampered.
 *
 * Send KE3 to the server to complete the handshake.
 *
 * @param agent_handle  Handle from opaque_agent_create().
 * @param ke2           Server's 1377-byte KE2 message.
 * @param ke2_length    Must be OPAQUE_KE2_LENGTH (1377).
 * @param state_handle  Same state used in generate_ke1.
 * @param ke3_out       Output buffer (must be >= OPAQUE_KE3_LENGTH bytes).
 * @param ke3_length    Size of ke3_out.
 * @param out_error     Optional; populated on failure.
 * @return OPAQUE_SUCCESS or an error code.
 */
OPAQUE_API OpaqueErrorCode opaque_agent_generate_ke3(
    OpaqueAgentHandle*      agent_handle,
    const uint8_t*          ke2,
    size_t                  ke2_length,
    OpaqueAgentStateHandle* state_handle,
    uint8_t*                ke3_out,
    size_t                  ke3_length,
    OpaqueError*            out_error);

/**
 * Authentication step 3/3. Extracts the session key (64 bytes) and master key (32 bytes).
 *
 * Call after opaque_agent_generate_ke3() succeeds. Both keys are identical on
 * client and server. After this call all sensitive state is securely zeroized.
 *
 * @param agent_handle       Handle from opaque_agent_create() (reserved).
 * @param state_handle       Same state used in generate_ke3.
 * @param session_key_out    Output buffer for the 64-byte session key.
 * @param session_key_length Must be >= OPAQUE_SESSION_KEY_LENGTH (64).
 * @param master_key_out     Output buffer for the 32-byte master key.
 * @param master_key_length  Must be >= OPAQUE_MASTER_KEY_LENGTH (32).
 * @param out_error          Optional; populated on failure.
 * @return OPAQUE_SUCCESS or an error code.
 */
OPAQUE_API OpaqueErrorCode opaque_agent_finish(
    OpaqueAgentHandle*      agent_handle,
    OpaqueAgentStateHandle* state_handle,
    uint8_t*                session_key_out,
    size_t                  session_key_length,
    uint8_t*                master_key_out,
    size_t                  master_key_length,
    OpaqueError*            out_error);

/* ── Wire-size queries (infallible) ───────────────────────────────────────── */

/** Returns OPAQUE_KE1_LENGTH (1273). */
OPAQUE_API size_t opaque_get_ke1_length(void);
/** Returns OPAQUE_KE2_LENGTH (1377). */
OPAQUE_API size_t opaque_get_ke2_length(void);
/** Returns OPAQUE_KE3_LENGTH (65). */
OPAQUE_API size_t opaque_get_ke3_length(void);
/** Returns OPAQUE_REGISTRATION_RECORD_LENGTH (169). */
OPAQUE_API size_t opaque_get_registration_record_length(void);
/** Returns OPAQUE_REGISTRATION_REQUEST_LENGTH (33). */
OPAQUE_API size_t opaque_get_registration_request_length(void);
/** Returns OPAQUE_REGISTRATION_RESPONSE_LENGTH (65). */
OPAQUE_API size_t opaque_get_registration_response_length(void);
/** Returns OPAQUE_KEM_PUBLIC_KEY_LENGTH (1184). */
OPAQUE_API size_t opaque_get_kem_public_key_length(void);
/** Returns OPAQUE_KEM_CIPHERTEXT_LENGTH (1088). */
OPAQUE_API size_t opaque_get_kem_ciphertext_length(void);

#ifdef __cplusplus
}
#endif
