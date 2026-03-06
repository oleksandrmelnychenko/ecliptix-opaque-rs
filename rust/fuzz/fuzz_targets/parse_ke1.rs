#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = opaque_core::protocol::parse_ke1(data);
});
