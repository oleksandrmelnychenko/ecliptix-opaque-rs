import Foundation

public final class OpaqueAgent: @unchecked Sendable {

    private var handle: OpaquePointer?
    private let lock = NSLock()

    private nonisolated(unsafe) static var isInitialized = false
    private static let initLock = NSLock()

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

    public func createState() throws -> AgentState {
        try AgentState()
    }

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

    public func withSessionKey<T>(_ body: (Data) throws -> T) throws -> T {
        lock.lock()
        defer { lock.unlock() }
        guard !disposed else { throw OpaqueError.invalidState }
        return try body(_sessionKey)
    }

    public func withMasterKey<T>(_ body: (Data) throws -> T) throws -> T {
        lock.lock()
        defer { lock.unlock() }
        guard !disposed else { throw OpaqueError.invalidState }
        return try body(_masterKey)
    }

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
    public enum Constants {
        public static let publicKeyLength = 32
        public static let privateKeyLength = 32
        public static let registrationRequestLength = 32
        public static let registrationResponseLength = 64
        public static let registrationRecordLength = 168
        public static let sessionKeyLength = 64
        public static let masterKeyLength = 32
        public static let ke1Length = 1272
        public static let ke2Length = 1376
        public static let ke3Length = 64
        public static let kemPublicKeyLength = 1184
        public static let kemCiphertextLength = 1088
    }
}
