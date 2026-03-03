// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

//! # Ecliptix OPAQUE FFI
//!
//! C-compatible Foreign Function Interface for the Ecliptix hybrid post-quantum OPAQUE protocol.
//! This crate exposes the agent (client) and relay (server) APIs as `extern "C"` functions
//! suitable for consumption from Swift, Kotlin, C, or any language with C FFI support.
//!
//! ## Wire sizes (bytes)
//!
//! | Constant                       | Value |
//! |--------------------------------|------:|
//! | `PUBLIC_KEY_LENGTH`            |    32 |
//! | `PRIVATE_KEY_LENGTH`           |    32 |
//! | `OPRF_SEED_LENGTH`             |    32 |
//! | `REGISTRATION_REQUEST_WIRE_LENGTH`  |    33 |
//! | `REGISTRATION_RESPONSE_WIRE_LENGTH` |    65 |
//! | `REGISTRATION_RECORD_LENGTH`   |   169 |
//! | `KE1_LENGTH`                   |  1273 |
//! | `KE2_LENGTH`                   |  1377 |
//! | `KE3_LENGTH`                   |    65 |
//! | `HASH_LENGTH` (session key)    |    64 |
//! | `MASTER_KEY_LENGTH`            |    32 |
//!
//! ## Return codes
//!
//! Every function returns `i32`. Zero means success; negative values are errors:
//!
//! | Code  | Meaning                                    |
//! |------:|--------------------------------------------|
//! |   `0` | Success                                    |
//! |  `-1` | Invalid input parameter                    |
//! |  `-2` | Cryptographic operation failed             |
//! |  `-3` | Protocol message has invalid format/length |
//! |  `-4` | Validation failed (wrong phase or expired) |
//! |  `-5` | Authentication failed (bad password or MAC)|
//! |  `-6` | Invalid public key                         |
//! |  `-7` | Account already registered                 |
//! |  `-8` | Malformed ML-KEM key or ciphertext         |
//! |  `-9` | Envelope has invalid format                |
//! | `-10` | Unsupported protocol version               |
//! | `-99` | Internal panic (should never happen)        |
//! |`-100` | Handle is busy (concurrent call rejected)  |
//!
//! ## Thread safety
//!
//! Each handle carries an atomic busy flag. A second call on the same handle while the first
//! is still running returns `-100` (`FFI_BUSY`). Different handles can be used concurrently.

mod agent_ffi;
mod relay_ffi;

use opaque_core::types::OpaqueResult;

pub(crate) fn result_to_int(r: OpaqueResult<()>) -> i32 {
    match r {
        Ok(()) => 0,
        Err(e) => e.to_c_int(),
    }
}
