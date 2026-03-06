// Copyright (c) 2026 Oleksandr Melnychenko. All rights reserved.
// SPDX-License-Identifier: MIT

//! # Ecliptix OPAQUE FFI
//!
//! C-compatible Foreign Function Interface for the Ecliptix hybrid
//! post-quantum OPAQUE protocol.
//!
//! Exposes the agent (client) and relay (server) APIs as `extern "C"`
//! functions suitable for consumption from Swift, C, or any language with
//! C FFI support.

mod agent_ffi;
mod relay_ffi;

use std::ffi::{c_char, CString};

// ── Error code ───────────────────────────────────────────────────────────────

/// C-compatible error code. Matches `OpaqueErrorCode` in `opaque_common.h`.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpaqueErrorCode {
    Success = 0,
    InvalidInput = -1,
    Crypto = -2,
    InvalidFormat = -3,
    Validation = -4,
    AuthFailed = -5,
    InvalidKey = -6,
    AlreadyRegistered = -7,
    MlKem = -8,
    InvalidEnvelope = -9,
    UnsupportedVersion = -10,
    Internal = -99,
    Busy = -100,
}

impl From<opaque_core::types::OpaqueError> for OpaqueErrorCode {
    fn from(e: opaque_core::types::OpaqueError) -> Self {
        use opaque_core::types::OpaqueError::*;
        match e {
            InvalidInput => Self::InvalidInput,
            CryptoError => Self::Crypto,
            InvalidProtocolMessage => Self::InvalidFormat,
            ValidationError => Self::Validation,
            AuthenticationError => Self::AuthFailed,
            InvalidPublicKey => Self::InvalidKey,
            AlreadyRegistered => Self::AlreadyRegistered,
            InvalidKemInput => Self::MlKem,
            InvalidEnvelope => Self::InvalidEnvelope,
            UnsupportedVersion => Self::UnsupportedVersion,
        }
    }
}

// ── Error struct ─────────────────────────────────────────────────────────────

/// C-compatible error struct. Matches `OpaqueError` in `opaque_common.h`.
///
/// Zero-initialise before each call:
///   `OpaqueError err = { OPAQUE_SUCCESS, NULL };`
///
/// `message` is heap-allocated by the library. Call `opaque_error_free()`
/// after inspecting it to avoid leaking memory.
#[repr(C)]
pub struct OpaqueError {
    pub code: OpaqueErrorCode,
    pub message: *mut c_char,
}

/// Writes an error code and message into an optional `out_error` out-pointer.
///
/// # Safety
/// `out_error` must be null or point to a valid `OpaqueError`.
pub(crate) unsafe fn write_error(out_error: *mut OpaqueError, code: OpaqueErrorCode, msg: &str) {
    if out_error.is_null() {
        return;
    }
    let prior = (*out_error).message;
    if !prior.is_null() {
        drop(CString::from_raw(prior));
    }
    let c_msg = CString::new(msg).unwrap_or_else(|_| CString::new("error").unwrap());
    (*out_error).code = code;
    (*out_error).message = c_msg.into_raw();
}

/// Converts a core `OpaqueError` to an `OpaqueErrorCode`, writing details into
/// `out_error` if non-null.
///
/// # Safety
/// `out_error` must be null or point to a valid `OpaqueError`.
pub(crate) unsafe fn write_core_error(
    out_error: *mut OpaqueError,
    e: opaque_core::types::OpaqueError,
) -> OpaqueErrorCode {
    let code = OpaqueErrorCode::from(e);
    write_error(out_error, code, &e.to_string());
    code
}

/// Catches a Rust panic and maps it to `OpaqueErrorCode::Internal`.
///
/// Usage:
/// ```ignore
/// ffi_catch_panic!(out_error, {
///     // ... fallible code that returns OpaqueErrorCode
/// })
/// ```
macro_rules! ffi_catch_panic {
    ($out_error:expr, $body:block) => {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $body)) {
            Ok(code) => code,
            Err(_) => {
                unsafe {
                    $crate::write_error(
                        $out_error,
                        $crate::OpaqueErrorCode::Internal,
                        "internal panic",
                    )
                };
                $crate::OpaqueErrorCode::Internal
            }
        }
    };
}
pub(crate) use ffi_catch_panic;

pub(crate) fn result_to_int<T>(result: opaque_core::types::OpaqueResult<T>) -> i32 {
    match result {
        Ok(_) => OpaqueErrorCode::Success as i32,
        Err(err) => OpaqueErrorCode::from(err) as i32,
    }
}

// ── Library lifecycle ─────────────────────────────────────────────────────────

/// Returns the library version string ("1.0.0"). Statically allocated; do not free.
#[no_mangle]
pub extern "C" fn opaque_version() -> *const c_char {
    c"1.0.0".as_ptr()
}

/// Initialises the library. Call once before any other function.
#[no_mangle]
pub extern "C" fn opaque_init() -> OpaqueErrorCode {
    OpaqueErrorCode::Success
}

/// Releases library resources. Safe to call multiple times.
#[no_mangle]
pub extern "C" fn opaque_shutdown() {}

// ── Error utilities ───────────────────────────────────────────────────────────

/// Frees the `message` field of `error` and resets it to null.
/// Does NOT free the OpaqueError struct itself (caller-owned).
/// Safe on a zero-initialised or already-freed struct.
///
/// # Safety
/// `error` must be null or point to a valid `OpaqueError`.
#[no_mangle]
pub unsafe extern "C" fn opaque_error_free(error: *mut OpaqueError) {
    if error.is_null() {
        return;
    }
    let msg = (*error).message;
    if !msg.is_null() {
        drop(CString::from_raw(msg));
        (*error).message = std::ptr::null_mut();
    }
}

/// Returns a static human-readable description for `code`. Statically allocated; do not free.
#[no_mangle]
pub extern "C" fn opaque_error_string(code: OpaqueErrorCode) -> *const c_char {
    let s: &std::ffi::CStr = match code {
        OpaqueErrorCode::Success => c"success",
        OpaqueErrorCode::InvalidInput => c"invalid input",
        OpaqueErrorCode::Crypto => c"cryptographic operation failed",
        OpaqueErrorCode::InvalidFormat => c"invalid message format",
        OpaqueErrorCode::Validation => c"validation failed",
        OpaqueErrorCode::AuthFailed => c"authentication failed",
        OpaqueErrorCode::InvalidKey => c"invalid public key",
        OpaqueErrorCode::AlreadyRegistered => c"account already registered",
        OpaqueErrorCode::MlKem => c"ML-KEM error",
        OpaqueErrorCode::InvalidEnvelope => c"invalid envelope",
        OpaqueErrorCode::UnsupportedVersion => c"unsupported protocol version",
        OpaqueErrorCode::Internal => c"internal error",
        OpaqueErrorCode::Busy => c"handle busy",
    };
    s.as_ptr()
}
