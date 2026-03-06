use std::ffi::{c_char, c_void, CStr};
use std::ptr;

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
}

fn fresh_error() -> FfiOpaqueError {
    FfiOpaqueError {
        code: 0,
        message: ptr::null_mut(),
    }
}

#[test]
fn ffi_error_struct_can_be_reused_safely() {
    unsafe {
        let zero_key = [0u8; 32];
        let mut handle = ptr::null_mut();
        let mut error = fresh_error();

        let first = opaque_agent_create(zero_key.as_ptr(), zero_key.len(), &mut handle, &mut error);
        assert_ne!(first, 0);
        assert!(!error.message.is_null());

        let first_message = CStr::from_ptr(error.message).to_string_lossy().into_owned();
        assert!(!first_message.is_empty());

        let second =
            opaque_agent_create(zero_key.as_ptr(), zero_key.len(), &mut handle, &mut error);
        assert_ne!(second, 0);
        assert!(!error.message.is_null());

        let second_message = CStr::from_ptr(error.message).to_string_lossy().into_owned();
        assert!(!second_message.is_empty());

        opaque_error_free(&mut error);
        assert!(error.message.is_null());
        assert!(handle.is_null());
    }
}
