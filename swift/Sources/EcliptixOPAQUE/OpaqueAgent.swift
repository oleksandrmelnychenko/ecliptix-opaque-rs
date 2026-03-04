import Foundation

/// Client-side handle for the Ecliptix Hybrid PQ-OPAQUE protocol.
///
/// `OpaqueAgent` wraps the Rust FFI and provides a safe Swift interface for
/// password registration and authentication using a hybrid post-quantum OPAQUE
/// protocol (4-DH Ristretto255 + ML-KEM-768).
///
/// ## Quick Start
///
/// ```swift
/// // One-time initialization
/// try OpaqueAgent.initialize()
///
/// let agent = try OpaqueAgent(relayPublicKey: serverPublicKey)
///
/// // --- Registration (one-time per account) ---
/// let state = try agent.createState()
/// let request = try agent.createRegistrationRequest(password: pwd, state: state)
/// // send request → server, receive response
/// let record = try agent.finalizeRegistration(response: response, state: state)
/// // send record → server for storage
/// state.dispose()
///
/// // --- Authentication (each login) ---
/// let loginState = try agent.createState()
/// let ke1 = try agent.generateKE1(password: pwd, state: loginState)
/// // send ke1 → server, receive ke2
/// let ke3 = try agent.generateKE3(ke2: ke2, state: loginState)
/// // send ke3 → server
/// let keys = try agent.finish(state: loginState)
/// // use keys.withSessionKey { ... }
/// keys.dispose()
/// loginState.dispose()
/// ```
///
/// ## Thread Safety
///
/// Each handle carries an internal lock. Concurrent calls on the *same* handle
/// are serialized. Different handles can be used from different threads freely.
public final class OpaqueAgent: @unchecked Sendable {

    private var handle: OpaquePointer?
    private let lock = NSLock()

    private nonisolated(unsafe) static var isInitialized = false
    private static let initLock = NSLock()

    /// Initializes the underlying cryptographic library.
    ///
    /// Must be called once before creating any `OpaqueAgent` instances.
    /// Safe to call multiple times — subsequent calls are no-ops.
    ///
    /// - Throws: ``OpaqueError/cryptoError(_:)`` if native initialization fails.
    public static func initialize() throws {
        initLock.lock()
        defer { initLock.unlock() }

        if isInitialized { return }

        let result = opaque_init()
        guard result >= 0 else {
            throw OpaqueError.cryptoError("Failed to initialize cryptographic library")
        }

        isInitialized = true

        precondition(
            opaque_get_ke1_length() == Constants.ke1Length,
            "KE1 length mismatch: Swift=\(Constants.ke1Length), Rust=\(opaque_get_ke1_length())"
        )
        precondition(
            opaque_get_ke2_length() == Constants.ke2Length,
            "KE2 length mismatch: Swift=\(Constants.ke2Length), Rust=\(opaque_get_ke2_length())"
        )
        precondition(
            opaque_get_ke3_length() == Constants.ke3Length,
            "KE3 length mismatch: Swift=\(Constants.ke3Length), Rust=\(opaque_get_ke3_length())"
        )
        precondition(
            opaque_get_registration_record_length() == Constants.registrationRecordLength,
            "Registration record length mismatch"
        )
    }

    internal static var initialized: Bool {
        initLock.lock()
        defer { initLock.unlock() }
        return isInitialized
    }

    /// Creates a new agent bound to a relay's static public key.
    ///
    /// - Parameter relayPublicKey: The relay's 32-byte Ristretto255 public key,
    ///   typically pinned in the app or fetched over TLS during setup.
    /// - Throws: ``OpaqueError/notInitialized`` if ``initialize()`` has not been called,
    ///   ``OpaqueError/invalidPublicKey`` if the key is not a valid Ristretto255 point.
    public init(relayPublicKey: Data) throws {
        guard Self.initialized else {
            throw OpaqueError.notInitialized
        }

        guard relayPublicKey.count == Constants.publicKeyLength else {
            throw OpaqueError.invalidInput(
                "Relay public key must be \(Constants.publicKeyLength) bytes"
            )
        }

        var rawHandle: UnsafeMutableRawPointer?
        let result = relayPublicKey.withUnsafeBytes { keyPtr in
            opaque_agent_create(
                keyPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                relayPublicKey.count,
                &rawHandle
            )
        }

        guard result == 0, let validHandle = rawHandle else {
            throw OpaqueError.fromCode(result)
        }

        self.handle = OpaquePointer(validHandle)
    }

    deinit {
        lock.lock()
        let h = handle
        handle = nil
        lock.unlock()
        if let h {
            opaque_agent_destroy(UnsafeMutableRawPointer(h))
        }
    }

    /// Creates a fresh protocol state for one registration or authentication session.
    ///
    /// Each state must be used for exactly one operation (registration *or* login),
    /// then disposed. States expire after 5 minutes.
    ///
    /// - Returns: A new ``AgentState`` instance.
    public func createState() throws -> AgentState {
        try AgentState()
    }

    /// **Registration step 1/2.** Creates an OPRF-blinded registration request.
    ///
    /// - Parameters:
    ///   - password: The user's password as raw bytes (1–4096 bytes).
    ///   - state: A fresh state from ``createState()``.
    /// - Returns: A 33-byte registration request to send to the server.
    public func createRegistrationRequest(password: Data, state: AgentState) throws -> Data {
        guard !password.isEmpty else {
            throw OpaqueError.invalidInput("Password cannot be empty")
        }

        lock.lock()
        defer { lock.unlock() }

        guard let handle = handle else {
            throw OpaqueError.invalidState
        }

        var request = Data(count: Constants.registrationRequestLength)

        let result = try state.withHandle { stateHandle in
            password.withUnsafeBytes { passwordPtr in
                request.withUnsafeMutableBytes { requestPtr in
                    opaque_agent_create_registration_request(
                        UnsafeMutableRawPointer(handle),
                        passwordPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        password.count,
                        stateHandle,
                        requestPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        Constants.registrationRequestLength
                    )
                }
            }
        }

        guard result == 0 else {
            throw OpaqueError.fromCode(result)
        }

        return request
    }

    /// **Registration step 2/2.** Finalizes registration using the server's response.
    ///
    /// - Parameters:
    ///   - response: The server's 65-byte registration response.
    ///   - state: The same state used in ``createRegistrationRequest(password:state:)``.
    /// - Returns: A 169-byte registration record to send to the server for storage.
    /// - Throws: ``OpaqueError/authenticationError`` if the server's public key
    ///   doesn't match the one given at agent creation (MITM protection).
    public func finalizeRegistration(response: Data, state: AgentState) throws -> Data {
        lock.lock()
        defer { lock.unlock() }

        guard let handle = handle else {
            throw OpaqueError.invalidState
        }

        guard response.count == Constants.registrationResponseLength else {
            throw OpaqueError.invalidInput(
                "Response must be \(Constants.registrationResponseLength) bytes"
            )
        }

        var record = Data(count: Constants.registrationRecordLength)

        let result = try state.withHandle { stateHandle in
            response.withUnsafeBytes { responsePtr in
                record.withUnsafeMutableBytes { recordPtr in
                    opaque_agent_finalize_registration(
                        UnsafeMutableRawPointer(handle),
                        responsePtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        response.count,
                        stateHandle,
                        recordPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        Constants.registrationRecordLength
                    )
                }
            }
        }

        guard result == 0 else {
            throw OpaqueError.fromCode(result)
        }

        return record
    }

    /// **Authentication step 1/3.** Generates the first key-exchange message (KE1).
    ///
    /// - Parameters:
    ///   - password: The user's password as raw bytes.
    ///   - state: A fresh state from ``createState()``.
    /// - Returns: A 1273-byte KE1 message to send to the server along with the account identifier.
    public func generateKE1(password: Data, state: AgentState) throws -> Data {
        guard !password.isEmpty else {
            throw OpaqueError.invalidInput("Password cannot be empty")
        }

        lock.lock()
        defer { lock.unlock() }

        guard let handle = handle else {
            throw OpaqueError.invalidState
        }

        var ke1 = Data(count: Constants.ke1Length)

        let result = try state.withHandle { stateHandle in
            password.withUnsafeBytes { passwordPtr in
                ke1.withUnsafeMutableBytes { ke1Ptr in
                    opaque_agent_generate_ke1(
                        UnsafeMutableRawPointer(handle),
                        passwordPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        password.count,
                        stateHandle,
                        ke1Ptr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        Constants.ke1Length
                    )
                }
            }
        }

        guard result == 0 else {
            throw OpaqueError.fromCode(result)
        }

        return ke1
    }

    /// **Authentication step 2/3.** Processes the server's KE2 and produces KE3.
    ///
    /// Internally decrypts the credential envelope, recovers the client's private key,
    /// and verifies the server's MAC. If the password is wrong or KE2 was tampered with,
    /// this method throws.
    ///
    /// - Parameters:
    ///   - ke2: The server's 1377-byte KE2 message.
    ///   - state: The same state used in ``generateKE1(password:state:)``.
    /// - Returns: A 65-byte KE3 message (client MAC) to send to the server.
    /// - Throws: ``OpaqueError/authenticationError`` on wrong password or tampered KE2.
    public func generateKE3(ke2: Data, state: AgentState) throws -> Data {
        lock.lock()
        defer { lock.unlock() }

        guard let handle = handle else {
            throw OpaqueError.invalidState
        }

        guard ke2.count == Constants.ke2Length else {
            throw OpaqueError.invalidInput(
                "KE2 must be \(Constants.ke2Length) bytes"
            )
        }

        var ke3 = Data(count: Constants.ke3Length)

        let result = try state.withHandle { stateHandle in
            ke2.withUnsafeBytes { ke2Ptr in
                ke3.withUnsafeMutableBytes { ke3Ptr in
                    opaque_agent_generate_ke3(
                        UnsafeMutableRawPointer(handle),
                        ke2Ptr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        ke2.count,
                        stateHandle,
                        ke3Ptr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        Constants.ke3Length
                    )
                }
            }
        }

        guard result == 0 else {
            throw OpaqueError.fromCode(result)
        }

        return ke3
    }

    /// **Authentication step 3/3.** Extracts the shared session and master keys.
    ///
    /// Call this after ``generateKE3(ke2:state:)`` succeeds. The returned keys are
    /// memory-locked and must be explicitly disposed after use.
    ///
    /// - Parameter state: The same state used throughout this authentication session.
    /// - Returns: An ``AuthenticationKeys`` containing the 64-byte session key and 32-byte master key.
    public func finish(state: AgentState) throws -> AuthenticationKeys {
        lock.lock()
        defer { lock.unlock() }

        guard let handle = handle else {
            throw OpaqueError.invalidState
        }

        var sessionKey = Data(count: Constants.sessionKeyLength)
        var masterKey = Data(count: Constants.masterKeyLength)
        defer {
            secureZeroData(&sessionKey)
            secureZeroData(&masterKey)
        }

        let result = try state.withHandle { stateHandle in
            sessionKey.withUnsafeMutableBytes { sessionPtr in
                masterKey.withUnsafeMutableBytes { masterPtr in
                    opaque_agent_finish(
                        UnsafeMutableRawPointer(handle),
                        stateHandle,
                        sessionPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        Constants.sessionKeyLength,
                        masterPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        Constants.masterKeyLength
                    )
                }
            }
        }

        guard result == 0 else {
            throw OpaqueError.fromCode(result)
        }

        return AuthenticationKeys(sessionKey: sessionKey, masterKey: masterKey)
    }
}

extension OpaqueAgent {
    /// Ephemeral state for a single registration or authentication session.
    ///
    /// Create via ``OpaqueAgent/createState()``. Each state holds intermediate
    /// cryptographic material (OPRF blind, ephemeral keys, nonces) and expires
    /// after 5 minutes. Call ``dispose()`` when done.
    public final class AgentState: @unchecked Sendable {
        private var handle: OpaquePointer?
        private let lock = NSLock()

        internal init() throws {
            var rawHandle: UnsafeMutableRawPointer?
            let result = opaque_agent_state_create(&rawHandle)

            guard result == 0, let validHandle = rawHandle else {
                throw OpaqueError.fromCode(result)
            }

            self.handle = OpaquePointer(validHandle)
        }

        internal func withHandle<T>(_ body: (UnsafeMutableRawPointer) throws -> T) throws -> T {
            lock.lock()
            defer { lock.unlock() }
            guard let h = handle else {
                throw OpaqueError.invalidState
            }
            return try body(UnsafeMutableRawPointer(h))
        }

        /// Releases the native state and securely zeroizes its memory.
        ///
        /// Safe to call multiple times. Also called automatically on `deinit`.
        public func dispose() {
            lock.lock()
            let h = handle
            handle = nil
            lock.unlock()
            if let h {
                opaque_agent_state_destroy(UnsafeMutableRawPointer(h))
            }
        }

        deinit { dispose() }
    }
}

/// Shared cryptographic keys produced after a successful authentication.
///
/// Keys are memory-locked (`mlock`) to prevent swapping to disk.
/// Access them through ``withSessionKey(_:)`` and ``withMasterKey(_:)``,
/// then call ``dispose()`` to securely zeroize and unlock the memory.
///
/// - **Session key** (64 bytes): ephemeral key for encrypting the current session.
/// - **Master key** (32 bytes): stable key derived from the password, usable for
///   key derivation (e.g. encrypting local data).
public final class AuthenticationKeys: @unchecked Sendable {
    private var _sessionKey: Data
    private var _masterKey: Data
    private let lock = NSLock()
    private var disposed = false

    internal init(sessionKey: Data, masterKey: Data) {
        self._sessionKey = sessionKey
        self._masterKey = masterKey
        _sessionKey.withUnsafeMutableBytes { bytes in
            guard let base = bytes.baseAddress else { return }
            _ = mlock(base, bytes.count)
        }
        _masterKey.withUnsafeMutableBytes { bytes in
            guard let base = bytes.baseAddress else { return }
            _ = mlock(base, bytes.count)
        }
    }

    /// Accesses the 64-byte session key within a scoped closure.
    ///
    /// - Throws: ``OpaqueError/invalidState`` if already disposed.
    public func withSessionKey<T>(_ body: (Data) throws -> T) throws -> T {
        lock.lock()
        defer { lock.unlock() }
        guard !disposed else { throw OpaqueError.invalidState }
        return try body(_sessionKey)
    }

    /// Accesses the 32-byte master key within a scoped closure.
    ///
    /// - Throws: ``OpaqueError/invalidState`` if already disposed.
    public func withMasterKey<T>(_ body: (Data) throws -> T) throws -> T {
        lock.lock()
        defer { lock.unlock() }
        guard !disposed else { throw OpaqueError.invalidState }
        return try body(_masterKey)
    }

    /// Securely zeroizes both keys and unlocks the memory pages.
    ///
    /// Safe to call multiple times. Also called automatically on `deinit`.
    public func dispose() {
        lock.lock()
        defer { lock.unlock() }
        guard !disposed else { return }
        disposed = true
        _sessionKey.withUnsafeMutableBytes { bytes in
            guard let base = bytes.baseAddress else { return }
            secureZeroBytes(base.assumingMemoryBound(to: UInt8.self), bytes.count)
            munlock(base, bytes.count)
        }
        _masterKey.withUnsafeMutableBytes { bytes in
            guard let base = bytes.baseAddress else { return }
            secureZeroBytes(base.assumingMemoryBound(to: UInt8.self), bytes.count)
            munlock(base, bytes.count)
        }
        _sessionKey = Data()
        _masterKey = Data()
    }

    deinit { dispose() }
}

extension OpaqueAgent {
    /// Wire sizes and cryptographic constants used by the protocol.
    ///
    /// Wire message sizes include a 1-byte protocol version prefix.
    /// Key sizes are raw cryptographic material without the prefix.
    public enum Constants {
        /// Ristretto255 compressed public key (32 bytes).
        public static let publicKeyLength = 32
        /// Ristretto255 scalar private key (32 bytes).
        public static let privateKeyLength = 32
        /// Version prefix (1) + OPRF blinded element (32) = 33 bytes.
        public static let registrationRequestLength = 33
        /// Version prefix (1) + evaluated OPRF element (32) + relay public key (32) = 65 bytes.
        public static let registrationResponseLength = 65
        /// Version prefix (1) + envelope + public key material = 169 bytes.
        public static let registrationRecordLength = 169
        /// SHA-512 session key (64 bytes, no version prefix).
        public static let sessionKeyLength = 64
        /// HKDF-derived master key (32 bytes, no version prefix).
        public static let masterKeyLength = 32
        /// Version prefix (1) + OPRF request (32) + Ristretto255 ephemeral (32) + nonce (24) + ML-KEM-768 public key (1184) = 1273 bytes.
        public static let ke1Length = 1273
        /// Version prefix (1) + server credential response + KE2 key exchange components = 1377 bytes.
        public static let ke2Length = 1377
        /// Version prefix (1) + HMAC-SHA-512 MAC (64) = 65 bytes.
        public static let ke3Length = 65
        /// ML-KEM-768 encapsulation public key (1184 bytes).
        public static let kemPublicKeyLength = 1184
        /// ML-KEM-768 ciphertext (1088 bytes).
        public static let kemCiphertextLength = 1088
    }
}
