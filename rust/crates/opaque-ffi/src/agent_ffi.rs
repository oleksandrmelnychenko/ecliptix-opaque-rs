// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

//! # Agent (Client) FFI — for Swift / mobile integration
//!
//! Provides the client-side OPAQUE API over C FFI. A typical iOS/macOS app
//! imports `opaque_agent.h` and calls these functions through Swift's C interop.
//!
//! ## Lifecycle overview
//!
//! ```text
//! ┌─────────────────────── SETUP ───────────────────────┐
//! │ opaque_init()                                       │
//! │ opaque_agent_create(relay_pk, 32, &handle, NULL)    │
//! │ opaque_agent_state_create(&state, NULL)             │
//! └─────────────────────────────────────────────────────┘
//!
//! ┌─────────────── REGISTRATION (one-time) ─────────────┐
//! │ opaque_agent_create_registration_request(           │
//! │     handle, password, len,                          │
//! │     state, request_buf, 33, NULL)                   │
//! │         ──── send 33 bytes to server ───►           │
//! │         ◄─── receive 65 bytes ──────────            │
//! │ opaque_agent_finalize_registration(                 │
//! │     handle, response, 65,                           │
//! │     state, record_buf, 169, NULL)                   │
//! │         ──── send 169 bytes to server ──►           │
//! └─────────────────────────────────────────────────────┘
//!
//! ┌─────────────── AUTHENTICATION (each login) ─────────┐
//! │ opaque_agent_state_create(&state, NULL)  // fresh   │
//! │ opaque_agent_generate_ke1(                          │
//! │     handle, password, len,                          │
//! │     state, ke1_buf, 1273, NULL)                     │
//! │         ──── send 1273 bytes to server ──►          │
//! │         ◄─── receive 1377 bytes ──────────          │
//! │ opaque_agent_generate_ke3(                          │
//! │     handle, ke2, 1377,                              │
//! │     state, ke3_buf, 65, NULL)                       │
//! │         ──── send 65 bytes to server ───►           │
//! │ opaque_agent_finish(                                │
//! │     handle, state,                                  │
//! │     session_key_buf, 64,                            │
//! │     master_key_buf, 32, NULL)                       │
//! └─────────────────────────────────────────────────────┘
//!
//! ┌─────────────────── CLEANUP ─────────────────────────┐
//! │ opaque_agent_state_destroy(&state)                  │
//! │ opaque_agent_destroy(&handle)                       │
//! └─────────────────────────────────────────────────────┘
//! ```

use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};

use zeroize::Zeroize;

use opaque_agent::{
    create_registration_request, finalize_registration, generate_ke1, generate_ke3,
    initiator_finish, InitiatorState, Ke1Message, Ke3Message, OpaqueInitiator, RegistrationRecord,
    RegistrationRequest,
};
use opaque_core::protocol;
use opaque_core::types::{
    pq, HASH_LENGTH, KE1_LENGTH, KE2_LENGTH, KE3_LENGTH, MASTER_KEY_LENGTH, PUBLIC_KEY_LENGTH,
    REGISTRATION_RECORD_LENGTH, REGISTRATION_REQUEST_WIRE_LENGTH,
    REGISTRATION_RESPONSE_WIRE_LENGTH,
};

use crate::{ffi_catch_panic, write_core_error, write_error, OpaqueError, OpaqueErrorCode};

// ── Typed handle types ────────────────────────────────────────────────────────

/// Typed agent handle. Forward-declared as `struct OpaqueAgentHandle` in C.
pub struct OpaqueAgentHandle {
    initiator: OpaqueInitiator,
    in_use: AtomicBool,
}

impl Drop for OpaqueAgentHandle {
    fn drop(&mut self) {
        self.initiator.zeroize();
    }
}

/// Typed per-flow state handle. Forward-declared as `struct OpaqueAgentStateHandle` in C.
pub struct OpaqueAgentStateHandle {
    state: InitiatorState,
    in_use: AtomicBool,
}

impl Drop for OpaqueAgentStateHandle {
    fn drop(&mut self) {
        self.state.zeroize();
    }
}

// ── Busy guard ────────────────────────────────────────────────────────────────

struct BusyGuard<'a>(&'a AtomicBool);

impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

// ── Acquire helpers ───────────────────────────────────────────────────────────

unsafe fn acquire_agent(
    handle: *mut OpaqueAgentHandle,
) -> Option<(&'static OpaqueAgentHandle, BusyGuard<'static>)> {
    if handle.is_null() {
        return None;
    }
    let in_use = &(*handle).in_use;
    if in_use.swap(true, Ordering::Acquire) {
        return None;
    }
    Some((&*handle, BusyGuard(in_use)))
}

unsafe fn acquire_agent_state(
    handle: *mut OpaqueAgentStateHandle,
) -> Option<(&'static mut OpaqueAgentStateHandle, BusyGuard<'static>)> {
    if handle.is_null() {
        return None;
    }
    let in_use = &*ptr::addr_of!((*handle).in_use);
    if in_use.swap(true, Ordering::Acquire) {
        return None;
    }
    Some((&mut *handle, BusyGuard(in_use)))
}

// ── Handle management ─────────────────────────────────────────────────────────

/// Creates a new agent handle bound to a specific relay's public key.
///
/// # Safety
/// - `relay_public_key` must point to at least `key_length` readable bytes.
/// - `out_handle` must be a valid non-null pointer that receives the new handle.
/// - `out_error` must be null or point to a valid `OpaqueError`.
#[no_mangle]
pub unsafe extern "C" fn opaque_agent_create(
    relay_public_key: *const u8,
    key_length: usize,
    out_handle: *mut *mut OpaqueAgentHandle,
    out_error: *mut OpaqueError,
) -> OpaqueErrorCode {
    ffi_catch_panic!(out_error, {
        if relay_public_key.is_null() || key_length != PUBLIC_KEY_LENGTH || out_handle.is_null() {
            write_error(out_error, OpaqueErrorCode::InvalidInput, "invalid input");
            return OpaqueErrorCode::InvalidInput;
        }
        let key = std::slice::from_raw_parts(relay_public_key, key_length);
        let initiator = match OpaqueInitiator::new(key) {
            Ok(i) => i,
            Err(e) => return write_core_error(out_error, e),
        };
        let boxed = Box::new(OpaqueAgentHandle {
            initiator,
            in_use: AtomicBool::new(false),
        });
        *out_handle = Box::into_raw(boxed);
        OpaqueErrorCode::Success
    })
}

/// Destroys an agent handle, securely zeroizing all key material.
///
/// Sets `*handle_ptr` to null. Safe to call on a null pointer.
///
/// # Safety
/// `handle_ptr` must be null or point to a valid `OpaqueAgentHandle*` from
/// `opaque_agent_create`.
#[no_mangle]
pub unsafe extern "C" fn opaque_agent_destroy(handle_ptr: *mut *mut OpaqueAgentHandle) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if handle_ptr.is_null() {
            return;
        }
        let handle = *handle_ptr;
        if handle.is_null() {
            return;
        }
        if (*handle).in_use.swap(true, Ordering::Acquire) {
            return;
        }
        *handle_ptr = ptr::null_mut();
        drop(Box::from_raw(handle));
    }));
}

/// Allocates a fresh per-flow state for one registration or authentication attempt.
///
/// # Safety
/// - `out_handle` must be a valid non-null pointer that receives the new state.
/// - `out_error` must be null or point to a valid `OpaqueError`.
#[no_mangle]
pub unsafe extern "C" fn opaque_agent_state_create(
    out_handle: *mut *mut OpaqueAgentStateHandle,
    out_error: *mut OpaqueError,
) -> OpaqueErrorCode {
    ffi_catch_panic!(out_error, {
        if out_handle.is_null() {
            write_error(
                out_error,
                OpaqueErrorCode::InvalidInput,
                "out_handle is null",
            );
            return OpaqueErrorCode::InvalidInput;
        }
        let boxed = Box::new(OpaqueAgentStateHandle {
            state: InitiatorState::new(),
            in_use: AtomicBool::new(false),
        });
        *out_handle = Box::into_raw(boxed);
        OpaqueErrorCode::Success
    })
}

/// Destroys a per-flow state, securely zeroizing all cryptographic material.
///
/// Sets `*handle_ptr` to null. Safe to call on a null pointer.
///
/// # Safety
/// `handle_ptr` must be null or point to a valid `OpaqueAgentStateHandle*` from
/// `opaque_agent_state_create`.
#[no_mangle]
pub unsafe extern "C" fn opaque_agent_state_destroy(handle_ptr: *mut *mut OpaqueAgentStateHandle) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if handle_ptr.is_null() {
            return;
        }
        let handle = *handle_ptr;
        if handle.is_null() {
            return;
        }
        if (*handle).in_use.swap(true, Ordering::Acquire) {
            return;
        }
        *handle_ptr = ptr::null_mut();
        drop(Box::from_raw(handle));
    }));
}

// ── Registration ──────────────────────────────────────────────────────────────

/// Registration step 1/2. Produces a 33-byte OPRF-blinded registration request.
///
/// # Safety
/// All pointer parameters must be valid for their stated sizes.
/// `out_error` must be null or point to a valid `OpaqueError`.
#[no_mangle]
pub unsafe extern "C" fn opaque_agent_create_registration_request(
    agent_handle: *mut OpaqueAgentHandle,
    password: *const u8,
    password_length: usize,
    state_handle: *mut OpaqueAgentStateHandle,
    request_out: *mut u8,
    request_length: usize,
    out_error: *mut OpaqueError,
) -> OpaqueErrorCode {
    ffi_catch_panic!(out_error, {
        if password.is_null()
            || password_length == 0
            || request_out.is_null()
            || request_length < REGISTRATION_REQUEST_WIRE_LENGTH
        {
            write_error(out_error, OpaqueErrorCode::InvalidInput, "invalid input");
            return OpaqueErrorCode::InvalidInput;
        }

        let Some((_ah, _ag)) = acquire_agent(agent_handle) else {
            write_error(out_error, OpaqueErrorCode::Busy, "agent handle busy");
            return OpaqueErrorCode::Busy;
        };
        let Some((sh, _sg)) = acquire_agent_state(state_handle) else {
            write_error(out_error, OpaqueErrorCode::Busy, "state handle busy");
            return OpaqueErrorCode::Busy;
        };

        let key = std::slice::from_raw_parts(password, password_length);
        let mut request = RegistrationRequest::new();

        match create_registration_request(key, &mut request, &mut sh.state) {
            Ok(()) => {
                let out = std::slice::from_raw_parts_mut(request_out, request_length);
                match protocol::write_registration_request(&request.data, out) {
                    Ok(()) => OpaqueErrorCode::Success,
                    Err(e) => write_core_error(out_error, e),
                }
            }
            Err(e) => write_core_error(out_error, e),
        }
    })
}

/// Registration step 2/2. Creates the 169-byte encrypted registration record.
///
/// # Safety
/// All pointer parameters must be valid for their stated sizes.
/// `out_error` must be null or point to a valid `OpaqueError`.
#[no_mangle]
pub unsafe extern "C" fn opaque_agent_finalize_registration(
    agent_handle: *mut OpaqueAgentHandle,
    response: *const u8,
    response_length: usize,
    state_handle: *mut OpaqueAgentStateHandle,
    record_out: *mut u8,
    record_length: usize,
    out_error: *mut OpaqueError,
) -> OpaqueErrorCode {
    ffi_catch_panic!(out_error, {
        if response.is_null()
            || response_length != REGISTRATION_RESPONSE_WIRE_LENGTH
            || record_out.is_null()
            || record_length < REGISTRATION_RECORD_LENGTH
        {
            write_error(out_error, OpaqueErrorCode::InvalidInput, "invalid input");
            return OpaqueErrorCode::InvalidInput;
        }

        let Some((ah, _ag)) = acquire_agent(agent_handle) else {
            write_error(out_error, OpaqueErrorCode::Busy, "agent handle busy");
            return OpaqueErrorCode::Busy;
        };
        let Some((sh, _sg)) = acquire_agent_state(state_handle) else {
            write_error(out_error, OpaqueErrorCode::Busy, "state handle busy");
            return OpaqueErrorCode::Busy;
        };

        let resp = std::slice::from_raw_parts(response, response_length);
        let mut record = RegistrationRecord::new();

        match finalize_registration(&ah.initiator, resp, &mut sh.state, &mut record) {
            Ok(()) => {
                let out = std::slice::from_raw_parts_mut(record_out, record_length);
                match protocol::write_registration_record(
                    &record.envelope,
                    &record.initiator_public_key,
                    out,
                ) {
                    Ok(()) => OpaqueErrorCode::Success,
                    Err(e) => write_core_error(out_error, e),
                }
            }
            Err(e) => write_core_error(out_error, e),
        }
    })
}

// ── Authentication ────────────────────────────────────────────────────────────

/// Authentication step 1/3. Produces the 1273-byte KE1 message.
///
/// # Safety
/// All pointer parameters must be valid for their stated sizes.
/// `out_error` must be null or point to a valid `OpaqueError`.
#[no_mangle]
pub unsafe extern "C" fn opaque_agent_generate_ke1(
    agent_handle: *mut OpaqueAgentHandle,
    password: *const u8,
    password_length: usize,
    state_handle: *mut OpaqueAgentStateHandle,
    ke1_out: *mut u8,
    ke1_length: usize,
    out_error: *mut OpaqueError,
) -> OpaqueErrorCode {
    ffi_catch_panic!(out_error, {
        if agent_handle.is_null()
            || password.is_null()
            || password_length == 0
            || ke1_out.is_null()
            || ke1_length < KE1_LENGTH
        {
            write_error(out_error, OpaqueErrorCode::InvalidInput, "invalid input");
            return OpaqueErrorCode::InvalidInput;
        }

        let Some((_ah, _ag)) = acquire_agent(agent_handle) else {
            write_error(out_error, OpaqueErrorCode::Busy, "agent handle busy");
            return OpaqueErrorCode::Busy;
        };
        let Some((sh, _sg)) = acquire_agent_state(state_handle) else {
            write_error(out_error, OpaqueErrorCode::Busy, "state handle busy");
            return OpaqueErrorCode::Busy;
        };

        let key = std::slice::from_raw_parts(password, password_length);
        let mut ke1 = Ke1Message::new();

        match generate_ke1(key, &mut ke1, &mut sh.state) {
            Ok(()) => {
                let out = std::slice::from_raw_parts_mut(ke1_out, ke1_length);
                match protocol::write_ke1(
                    &ke1.credential_request,
                    &ke1.initiator_public_key,
                    &ke1.initiator_nonce,
                    &ke1.pq_ephemeral_public_key,
                    out,
                ) {
                    Ok(()) => OpaqueErrorCode::Success,
                    Err(e) => write_core_error(out_error, e),
                }
            }
            Err(e) => write_core_error(out_error, e),
        }
    })
}

/// Authentication step 2/3. Processes KE2 and produces the 65-byte KE3.
///
/// Returns `OpaqueErrorCode::AuthFailed` if the password is wrong or KE2 is tampered.
///
/// # Safety
/// All pointer parameters must be valid for their stated sizes.
/// `out_error` must be null or point to a valid `OpaqueError`.
#[no_mangle]
pub unsafe extern "C" fn opaque_agent_generate_ke3(
    agent_handle: *mut OpaqueAgentHandle,
    ke2: *const u8,
    ke2_length: usize,
    state_handle: *mut OpaqueAgentStateHandle,
    ke3_out: *mut u8,
    ke3_length: usize,
    out_error: *mut OpaqueError,
) -> OpaqueErrorCode {
    ffi_catch_panic!(out_error, {
        if ke2.is_null() || ke2_length != KE2_LENGTH || ke3_out.is_null() || ke3_length < KE3_LENGTH
        {
            write_error(out_error, OpaqueErrorCode::InvalidInput, "invalid input");
            return OpaqueErrorCode::InvalidInput;
        }

        let Some((ah, _ag)) = acquire_agent(agent_handle) else {
            write_error(out_error, OpaqueErrorCode::Busy, "agent handle busy");
            return OpaqueErrorCode::Busy;
        };
        let Some((sh, _sg)) = acquire_agent_state(state_handle) else {
            write_error(out_error, OpaqueErrorCode::Busy, "state handle busy");
            return OpaqueErrorCode::Busy;
        };

        let ke2_slice = std::slice::from_raw_parts(ke2, ke2_length);
        let mut ke3 = Ke3Message::new();

        match generate_ke3(&ah.initiator, ke2_slice, &mut sh.state, &mut ke3) {
            Ok(()) => {
                let out = std::slice::from_raw_parts_mut(ke3_out, ke3_length);
                match protocol::write_ke3(&ke3.initiator_mac, out) {
                    Ok(()) => OpaqueErrorCode::Success,
                    Err(e) => write_core_error(out_error, e),
                }
            }
            Err(e) => write_core_error(out_error, e),
        }
    })
}

/// Authentication step 3/3. Extracts the session key (64 bytes) and master key (32 bytes).
///
/// After this call all sensitive state is securely zeroized.
///
/// # Safety
/// All pointer parameters must be valid for their stated sizes.
/// `out_error` must be null or point to a valid `OpaqueError`.
#[no_mangle]
pub unsafe extern "C" fn opaque_agent_finish(
    _agent_handle: *mut OpaqueAgentHandle,
    state_handle: *mut OpaqueAgentStateHandle,
    session_key_out: *mut u8,
    session_key_length: usize,
    master_key_out: *mut u8,
    master_key_length: usize,
    out_error: *mut OpaqueError,
) -> OpaqueErrorCode {
    ffi_catch_panic!(out_error, {
        if session_key_out.is_null()
            || session_key_length < HASH_LENGTH
            || master_key_out.is_null()
            || master_key_length < MASTER_KEY_LENGTH
        {
            write_error(out_error, OpaqueErrorCode::InvalidInput, "invalid input");
            return OpaqueErrorCode::InvalidInput;
        }

        let Some((sh, _sg)) = acquire_agent_state(state_handle) else {
            write_error(out_error, OpaqueErrorCode::Busy, "state handle busy");
            return OpaqueErrorCode::Busy;
        };

        let mut session_key = [0u8; HASH_LENGTH];
        let mut master_key = [0u8; MASTER_KEY_LENGTH];

        let rc = match initiator_finish(&mut sh.state, &mut session_key, &mut master_key) {
            Ok(()) => {
                ptr::copy_nonoverlapping(session_key.as_ptr(), session_key_out, HASH_LENGTH);
                ptr::copy_nonoverlapping(master_key.as_ptr(), master_key_out, MASTER_KEY_LENGTH);
                OpaqueErrorCode::Success
            }
            Err(e) => write_core_error(out_error, e),
        };
        session_key.zeroize();
        master_key.zeroize();
        rc
    })
}

// ── Wire-size queries (infallible) ────────────────────────────────────────────

/// Returns `OPAQUE_KE1_LENGTH` (1273).
#[no_mangle]
pub extern "C" fn opaque_get_ke1_length() -> usize {
    KE1_LENGTH
}

/// Returns `OPAQUE_KE2_LENGTH` (1377).
#[no_mangle]
pub extern "C" fn opaque_get_ke2_length() -> usize {
    KE2_LENGTH
}

/// Returns `OPAQUE_KE3_LENGTH` (65).
#[no_mangle]
pub extern "C" fn opaque_get_ke3_length() -> usize {
    KE3_LENGTH
}

/// Returns `OPAQUE_REGISTRATION_RECORD_LENGTH` (169).
#[no_mangle]
pub extern "C" fn opaque_get_registration_record_length() -> usize {
    REGISTRATION_RECORD_LENGTH
}

/// Returns `OPAQUE_REGISTRATION_REQUEST_LENGTH` (33).
#[no_mangle]
pub extern "C" fn opaque_get_registration_request_length() -> usize {
    REGISTRATION_REQUEST_WIRE_LENGTH
}

/// Returns `OPAQUE_REGISTRATION_RESPONSE_LENGTH` (65).
#[no_mangle]
pub extern "C" fn opaque_get_registration_response_length() -> usize {
    REGISTRATION_RESPONSE_WIRE_LENGTH
}

/// Returns `OPAQUE_KEM_PUBLIC_KEY_LENGTH` (1184).
#[no_mangle]
pub extern "C" fn opaque_get_kem_public_key_length() -> usize {
    pq::KEM_PUBLIC_KEY_LENGTH
}

/// Returns `OPAQUE_KEM_CIPHERTEXT_LENGTH` (1088).
#[no_mangle]
pub extern "C" fn opaque_get_kem_ciphertext_length() -> usize {
    pq::KEM_CIPHERTEXT_LENGTH
}
