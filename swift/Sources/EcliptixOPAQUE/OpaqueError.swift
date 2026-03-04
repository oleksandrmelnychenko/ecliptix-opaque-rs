import Foundation

/// Errors produced by the Ecliptix OPAQUE protocol.
///
/// Maps directly to the native FFI return codes. Use `localizedDescription`
/// for human-readable messages suitable for logging.
public enum OpaqueError: Error, LocalizedError, Sendable {
    /// ``OpaqueAgent/initialize()`` has not been called yet.
    case notInitialized
    /// A parameter was invalid (details in the associated string).
    case invalidInput(String)
    /// A low-level cryptographic operation failed.
    case cryptoError(String)
    /// Memory allocation failed.
    case memoryError
    /// Protocol validation failed (wrong phase or expired state).
    case validationError
    /// Authentication failed — wrong password or message tampering detected.
    case authenticationError
    /// The supplied public key is not a valid Ristretto255 point.
    case invalidPublicKey
    /// The handle has been destroyed or is otherwise unusable.
    case invalidState
    /// An unmapped native error code.
    case unknown(Int32)

    public var errorDescription: String? {
        switch self {
        case .notInitialized:
            return "OPAQUE library not initialized. Call OpaqueAgent.initialize() first."
        case .invalidInput(let details):
            return "Invalid input: \(details)"
        case .cryptoError(let details):
            return "Cryptographic error: \(details)"
        case .memoryError:
            return "Memory allocation failed"
        case .validationError:
            return "Validation failed"
        case .authenticationError:
            return "Authentication failed — wrong password or message tampering detected"
        case .invalidPublicKey:
            return "Invalid public key format"
        case .invalidState:
            return "Invalid handle — may have been destroyed"
        case .unknown(let code):
            return "Unknown error (code: \(code))"
        }
    }

    internal static func fromCode(_ code: Int32) -> OpaqueError {
        switch code {
        case 0:
            return .invalidState
        case -1:
            return .invalidInput("Invalid parameters")
        case -2:
            return .cryptoError("Cryptographic operation failed")
        case -3:
            return .invalidInput("Invalid protocol message")
        case -4:
            return .validationError
        case -5:
            return .authenticationError
        case -6:
            return .invalidPublicKey
        case -7:
            return .invalidInput("Account already registered")
        case -8:
            return .cryptoError("Invalid KEM input")
        case -9:
            return .cryptoError("Invalid envelope format")
        case -99:
            return .cryptoError("Internal FFI panic")
        default:
            return .unknown(code)
        }
    }
}
