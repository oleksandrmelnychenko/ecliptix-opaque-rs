#pragma once
#include "opaque_export.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ── Version ─────────────────────────────────────────────────────────────── */

#define OPAQUE_API_VERSION_MAJOR 1
#define OPAQUE_API_VERSION_MINOR 0
#define OPAQUE_API_VERSION_PATCH 0
#define OPAQUE_LIBRARY_VERSION   "1.0.0"

/* ── Wire-size constants ──────────────────────────────────────────────────── */

/** KE1 message (version + OPRF element + ephemeral X25519 + nonce + ML-KEM-768 pk). */
#define OPAQUE_KE1_LENGTH                    1273
/** KE2 message. */
#define OPAQUE_KE2_LENGTH                    1377
/** KE3 message (client MAC). */
#define OPAQUE_KE3_LENGTH                      65

/** Registration request: version-prefixed OPRF-blinded element. */
#define OPAQUE_REGISTRATION_REQUEST_LENGTH     33
/** Registration response: version-prefixed OPRF output + server pk. */
#define OPAQUE_REGISTRATION_RESPONSE_LENGTH    65
/** Registration record stored server-side: encrypted envelope + client pk. */
#define OPAQUE_REGISTRATION_RECORD_LENGTH     169

/** Session key length (BLAKE2b-512 output). */
#define OPAQUE_SESSION_KEY_LENGTH              64
/** Master key length. */
#define OPAQUE_MASTER_KEY_LENGTH               32
/** Ristretto255 public key length. */
#define OPAQUE_PUBLIC_KEY_LENGTH               32
/** ML-KEM-768 public key length. */
#define OPAQUE_KEM_PUBLIC_KEY_LENGTH         1184
/** ML-KEM-768 ciphertext length. */
#define OPAQUE_KEM_CIPHERTEXT_LENGTH         1088

/* ── Error codes ─────────────────────────────────────────────────────────── */

typedef enum {
    OPAQUE_SUCCESS                   =    0,
    OPAQUE_ERROR_INVALID_INPUT       =   -1,
    OPAQUE_ERROR_CRYPTO              =   -2,
    OPAQUE_ERROR_INVALID_FORMAT      =   -3,
    OPAQUE_ERROR_VALIDATION          =   -4,
    OPAQUE_ERROR_AUTH_FAILED         =   -5,
    OPAQUE_ERROR_INVALID_KEY         =   -6,
    OPAQUE_ERROR_ALREADY_REGISTERED  =   -7,
    OPAQUE_ERROR_ML_KEM              =   -8,
    OPAQUE_ERROR_INVALID_ENVELOPE    =   -9,
    OPAQUE_ERROR_UNSUPPORTED_VERSION =  -10,
    OPAQUE_ERROR_INTERNAL            =  -99,
    OPAQUE_ERROR_BUSY                = -100
} OpaqueErrorCode;

/* ── Error struct ─────────────────────────────────────────────────────────── */

/**
 * Structured error returned via out-pointer parameters.
 *
 * `message` is heap-allocated by the library; call `opaque_error_free()`
 * after inspecting it to avoid leaking memory.
 * The struct itself is caller-allocated (stack is fine).
 *
 * Zero-initialise before each call:
 *   OpaqueError err = { OPAQUE_SUCCESS, NULL };
 */
typedef struct OpaqueError {
    OpaqueErrorCode code;
    char*           message;
} OpaqueError;

/* ── Opaque client handle types ──────────────────────────────────────────── */

/**
 * Agent (client) handle — owns the static keypair bound to the relay's
 * public key. Create with opaque_agent_create(); destroy with
 * opaque_agent_destroy(). Concurrent calls on the same handle return
 * OPAQUE_ERROR_BUSY.
 */
typedef struct OpaqueAgentHandle OpaqueAgentHandle;

/**
 * Per-flow agent state — one per registration or authentication attempt.
 * Create with opaque_agent_state_create(); destroy with
 * opaque_agent_state_destroy() after the flow completes or fails.
 * Has a 5-minute lifetime; subsequent calls after expiry return
 * OPAQUE_ERROR_VALIDATION.
 */
typedef struct OpaqueAgentStateHandle OpaqueAgentStateHandle;

/* ── Library lifecycle ────────────────────────────────────────────────────── */

/** Returns the library version string ("1.0.0"). Statically allocated; do not free. */
OPAQUE_API const char*      opaque_version(void);
/** Initialises the library. Call once before any other function. */
OPAQUE_API OpaqueErrorCode  opaque_init(void);
/** Releases library resources. Safe to call multiple times. */
OPAQUE_API void             opaque_shutdown(void);

/* ── Error utilities ──────────────────────────────────────────────────────── */

/**
 * Frees the `message` field of `error` and resets it to null.
 * Does NOT free the OpaqueError struct itself (caller-owned).
 * Safe on a zero-initialised or already-freed struct.
 */
OPAQUE_API void opaque_error_free(OpaqueError* error);

/**
 * Returns a static human-readable description for `code`.
 * Statically allocated; do not free.
 */
OPAQUE_API const char* opaque_error_string(OpaqueErrorCode code);

#ifdef __cplusplus
}
#endif
