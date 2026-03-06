import Foundation

@_exported import EcliptixOPAQUEBinary

internal typealias COpaqueError = EcliptixOPAQUEBinary.OpaqueError
internal typealias COpaqueErrorCode = EcliptixOPAQUEBinary.OpaqueErrorCode


extension COpaqueError {
    init() {
        self.init(code: COpaqueErrorCode(rawValue: 0), message: nil)
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
