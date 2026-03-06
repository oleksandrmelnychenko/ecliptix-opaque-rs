import Foundation

#if canImport(EcliptixOPAQUEBinary)
@_exported import EcliptixOPAQUEBinary

internal typealias COpaqueError = EcliptixOPAQUEBinary.OpaqueError
internal typealias COpaqueErrorCode = EcliptixOPAQUEBinary.OpaqueErrorCode

extension COpaqueError {
    init() {
        self.init(code: COpaqueErrorCode(rawValue: 0)!, message: nil)
    }
}

@inline(__always)
internal func coOpaqueErrorCodeRawValue(_ code: COpaqueErrorCode) -> Int32 {
    Int32(code.rawValue)
}

@inline(__always)
internal func coOpaqueErrorStaticMessage(_ code: COpaqueErrorCode) -> UnsafePointer<CChar>? {
    EcliptixOPAQUEBinary.opaque_error_string(code)
}
#else
// Temporary Swift ABI shim.
// This remains in place until the republished XCFramework ships the curated
// module map and canonical headers from `rust/include/`.

internal typealias COpaqueErrorCode = Int32

internal struct COpaqueError {
    var code: COpaqueErrorCode
    var message: UnsafeMutablePointer<CChar>?

    init() {
        code = 0
        message = nil
    }
}

@inline(__always)
internal func coOpaqueErrorCodeRawValue(_ code: COpaqueErrorCode) -> Int32 {
    code
}

@_silgen_name("opaque_version")
internal func opaque_version() -> UnsafePointer<CChar>?

@_silgen_name("opaque_init")
internal func opaque_init() -> Int32

@_silgen_name("opaque_shutdown")
internal func opaque_shutdown()

@_silgen_name("opaque_error_free")
internal func opaque_error_free(_ error: UnsafeMutablePointer<COpaqueError>?)

@_silgen_name("opaque_error_string")
internal func opaque_error_string(_ code: Int32) -> UnsafePointer<CChar>?

@inline(__always)
internal func coOpaqueErrorStaticMessage(_ code: COpaqueErrorCode) -> UnsafePointer<CChar>? {
    opaque_error_string(code)
}

@_silgen_name("opaque_agent_create")
internal func opaque_agent_create(
    _ relay_public_key: UnsafePointer<UInt8>?,
    _ key_length: Int,
    _ out_handle: UnsafeMutablePointer<OpaquePointer?>?,
    _ out_error: UnsafeMutablePointer<COpaqueError>?
) -> Int32

@_silgen_name("opaque_agent_destroy")
internal func opaque_agent_destroy(_ handle_ptr: UnsafeMutablePointer<OpaquePointer?>?)

@_silgen_name("opaque_agent_state_create")
internal func opaque_agent_state_create(
    _ out_handle: UnsafeMutablePointer<OpaquePointer?>?,
    _ out_error: UnsafeMutablePointer<COpaqueError>?
) -> Int32

@_silgen_name("opaque_agent_state_destroy")
internal func opaque_agent_state_destroy(_ handle_ptr: UnsafeMutablePointer<OpaquePointer?>?)

@_silgen_name("opaque_agent_create_registration_request")
internal func opaque_agent_create_registration_request(
    _ agent_handle: OpaquePointer?,
    _ password: UnsafePointer<UInt8>?,
    _ password_length: Int,
    _ state_handle: OpaquePointer?,
    _ request_out: UnsafeMutablePointer<UInt8>?,
    _ request_length: Int,
    _ out_error: UnsafeMutablePointer<COpaqueError>?
) -> Int32

@_silgen_name("opaque_agent_finalize_registration")
internal func opaque_agent_finalize_registration(
    _ agent_handle: OpaquePointer?,
    _ response: UnsafePointer<UInt8>?,
    _ response_length: Int,
    _ state_handle: OpaquePointer?,
    _ record_out: UnsafeMutablePointer<UInt8>?,
    _ record_length: Int,
    _ out_error: UnsafeMutablePointer<COpaqueError>?
) -> Int32

@_silgen_name("opaque_agent_generate_ke1")
internal func opaque_agent_generate_ke1(
    _ agent_handle: OpaquePointer?,
    _ password: UnsafePointer<UInt8>?,
    _ password_length: Int,
    _ state_handle: OpaquePointer?,
    _ ke1_out: UnsafeMutablePointer<UInt8>?,
    _ ke1_length: Int,
    _ out_error: UnsafeMutablePointer<COpaqueError>?
) -> Int32

@_silgen_name("opaque_agent_generate_ke3")
internal func opaque_agent_generate_ke3(
    _ agent_handle: OpaquePointer?,
    _ ke2: UnsafePointer<UInt8>?,
    _ ke2_length: Int,
    _ state_handle: OpaquePointer?,
    _ ke3_out: UnsafeMutablePointer<UInt8>?,
    _ ke3_length: Int,
    _ out_error: UnsafeMutablePointer<COpaqueError>?
) -> Int32

@_silgen_name("opaque_agent_finish")
internal func opaque_agent_finish(
    _ agent_handle: OpaquePointer?,
    _ state_handle: OpaquePointer?,
    _ session_key_out: UnsafeMutablePointer<UInt8>?,
    _ session_key_length: Int,
    _ master_key_out: UnsafeMutablePointer<UInt8>?,
    _ master_key_length: Int,
    _ out_error: UnsafeMutablePointer<COpaqueError>?
) -> Int32

@_silgen_name("opaque_get_ke1_length")
internal func opaque_get_ke1_length() -> Int

@_silgen_name("opaque_get_ke2_length")
internal func opaque_get_ke2_length() -> Int

@_silgen_name("opaque_get_ke3_length")
internal func opaque_get_ke3_length() -> Int

@_silgen_name("opaque_get_registration_request_length")
internal func opaque_get_registration_request_length() -> Int

@_silgen_name("opaque_get_registration_record_length")
internal func opaque_get_registration_record_length() -> Int

@_silgen_name("opaque_get_kem_public_key_length")
internal func opaque_get_kem_public_key_length() -> Int

@_silgen_name("opaque_get_kem_ciphertext_length")
internal func opaque_get_kem_ciphertext_length() -> Int
#endif
