#pragma once
#include "opaque_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Relay (server-side) API — Ecliptix OPAQUE
 *
 * This API is intended for backend and service integrations. Handles are
 * caller-owned, must not be used concurrently, and must be destroyed with the
 * matching destroy function.
 *
 * SECURITY NOTES:
 *   - Persist the relay private key and OPRF seed securely.
 *   - Compromise of the OPRF seed collapses offline-guessing resistance for
 *     registration records protected by that seed.
 *   - When exposing failures to untrusted clients, map all negative return
 *     codes to one generic authentication failure.
 */

/* ── Relay keypair management ─────────────────────────────────────────────── */

OPAQUE_API int32_t opaque_relay_keypair_generate(
    OpaqueRelayKeypairHandle** out_handle);

OPAQUE_API void opaque_relay_keypair_destroy(
    OpaqueRelayKeypairHandle** handle_ptr);

OPAQUE_API int32_t opaque_relay_keypair_get_public_key(
    OpaqueRelayKeypairHandle* handle,
    uint8_t*                 public_key,
    size_t                   key_buffer_size);

OPAQUE_API int32_t opaque_relay_keypair_get_oprf_seed(
    OpaqueRelayKeypairHandle* handle,
    uint8_t*                 oprf_seed,
    size_t                   seed_buffer_size);

/* ── Relay lifecycle ──────────────────────────────────────────────────────── */

OPAQUE_API int32_t opaque_relay_create(
    OpaqueRelayKeypairHandle* keypair_handle,
    OpaqueRelayHandle**       out_handle);

OPAQUE_API int32_t opaque_relay_create_with_keys(
    const uint8_t*      private_key,
    size_t              private_key_len,
    const uint8_t*      public_key,
    size_t              public_key_len,
    const uint8_t*      oprf_seed,
    size_t              oprf_seed_len,
    OpaqueRelayHandle** out_handle);

OPAQUE_API void opaque_relay_destroy(
    OpaqueRelayHandle** handle_ptr);

/* ── Relay per-flow state ─────────────────────────────────────────────────── */

OPAQUE_API int32_t opaque_relay_state_create(
    OpaqueRelayStateHandle** out_handle);

OPAQUE_API void opaque_relay_state_destroy(
    OpaqueRelayStateHandle** handle_ptr);

/* ── Registration ─────────────────────────────────────────────────────────── */

OPAQUE_API int32_t opaque_relay_create_registration_response(
    OpaqueRelayHandle* relay_handle,
    const uint8_t*     request_data,
    size_t             request_length,
    const uint8_t*     account_id,
    size_t             account_id_length,
    uint8_t*           response_data,
    size_t             response_buffer_size);

OPAQUE_API int32_t opaque_relay_build_credentials(
    const uint8_t* registration_record,
    size_t         record_length,
    uint8_t*       credentials_out,
    size_t         credentials_out_length);

/* ── Authentication ───────────────────────────────────────────────────────── */

OPAQUE_API int32_t opaque_relay_generate_ke2(
    OpaqueRelayHandle*      relay_handle,
    const uint8_t*          ke1_data,
    size_t                  ke1_length,
    const uint8_t*          account_id,
    size_t                  account_id_length,
    const uint8_t*          credentials_data,
    size_t                  credentials_length,
    uint8_t*                ke2_data,
    size_t                  ke2_buffer_size,
    OpaqueRelayStateHandle* state_handle);

OPAQUE_API int32_t opaque_relay_finish(
    OpaqueRelayHandle*      relay_handle,
    const uint8_t*          ke3_data,
    size_t                  ke3_length,
    OpaqueRelayStateHandle* state_handle,
    uint8_t*                session_key,
    size_t                  session_key_buffer_size,
    uint8_t*                master_key_out,
    size_t                  master_key_buffer_size);

/* ── Relay size queries ───────────────────────────────────────────────────── */

OPAQUE_API size_t opaque_relay_get_ke1_length(void);
OPAQUE_API size_t opaque_relay_get_ke2_length(void);
OPAQUE_API size_t opaque_relay_get_ke3_length(void);
OPAQUE_API size_t opaque_relay_get_registration_request_length(void);
OPAQUE_API size_t opaque_relay_get_registration_response_length(void);
OPAQUE_API size_t opaque_relay_get_registration_record_length(void);
OPAQUE_API size_t opaque_relay_get_credentials_length(void);
OPAQUE_API size_t opaque_relay_get_kem_ciphertext_length(void);
OPAQUE_API size_t opaque_relay_get_oprf_seed_length(void);

#ifdef __cplusplus
}
#endif
