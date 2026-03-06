#![no_main]

use std::ffi::{c_char, c_void};
use std::ptr;

use libfuzzer_sys::fuzz_target;
use opaque_ffi as _;

#[repr(C)]
struct FfiOpaqueError {
    code: i32,
    message: *mut c_char,
}

unsafe extern "C" {
    fn opaque_error_free(error: *mut FfiOpaqueError);
    fn opaque_agent_create(
        relay_public_key: *const u8,
        key_length: usize,
        out_handle: *mut *mut c_void,
        out_error: *mut FfiOpaqueError,
    ) -> i32;
    fn opaque_agent_destroy(handle_ptr: *mut *mut c_void);
    fn opaque_agent_state_create(
        out_handle: *mut *mut c_void,
        out_error: *mut FfiOpaqueError,
    ) -> i32;
    fn opaque_agent_state_destroy(handle_ptr: *mut *mut c_void);
    fn opaque_agent_create_registration_request(
        agent_handle: *mut c_void,
        password: *const u8,
        password_length: usize,
        state_handle: *mut c_void,
        request_out: *mut u8,
        request_length: usize,
        out_error: *mut FfiOpaqueError,
    ) -> i32;
}

fn fresh_error() -> FfiOpaqueError {
    FfiOpaqueError {
        code: 0,
        message: ptr::null_mut(),
    }
}

fuzz_target!(|data: &[u8]| {
    let (relay_pk, rest) = data.split_at(data.len().min(32));
    let password = rest;

    let mut error = fresh_error();
    let mut agent = ptr::null_mut();

    unsafe {
        let _ = opaque_agent_create(
            relay_pk.as_ptr(),
            relay_pk.len(),
            &mut agent,
            &mut error,
        );

        if !agent.is_null() {
            let mut state = ptr::null_mut();
            let mut state_error = fresh_error();
            let _ = opaque_agent_state_create(&mut state, &mut state_error);

            if !state.is_null() {
                let mut request_out = [0u8; 33];
                let request_len = if password.len() % 2 == 0 { 33 } else { password.len().min(33) };
                let _ = opaque_agent_create_registration_request(
                    agent,
                    password.as_ptr(),
                    password.len(),
                    state,
                    request_out.as_mut_ptr(),
                    request_len,
                    &mut state_error,
                );
                opaque_agent_state_destroy(&mut state);
            }

            opaque_error_free(&mut state_error);
            opaque_agent_destroy(&mut agent);
        }

        opaque_error_free(&mut error);
    }
});
