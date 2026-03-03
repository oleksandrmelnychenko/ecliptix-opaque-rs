import Foundation

public final class OpaqueRelay: @unchecked Sendable {

    private var handle: OpaquePointer?
    private let lock = NSLock()

    public init(keypair: KeyPair) throws {
        guard OpaqueAgent.initialized else {
            throw OpaqueError.notInitialized
        }

        var rawHandle: UnsafeMutableRawPointer?
        let result = opaque_relay_create(
            UnsafeMutableRawPointer(keypair.handle),
            &rawHandle
        )

        guard result == 0, let validHandle = rawHandle else {
            throw OpaqueError.fromCode(result)
        }

        self.handle = OpaquePointer(validHandle)
    }

    public init(privateKey: Data, publicKey: Data, oprfSeed: Data) throws {
        guard OpaqueAgent.initialized else {
            throw OpaqueError.notInitialized
        }

        guard privateKey.count == OpaqueAgent.Constants.privateKeyLength else {
            throw OpaqueError.invalidInput(
                "Private key must be \(OpaqueAgent.Constants.privateKeyLength) bytes"
            )
        }
        guard publicKey.count == OpaqueAgent.Constants.publicKeyLength else {
            throw OpaqueError.invalidInput(
                "Public key must be \(OpaqueAgent.Constants.publicKeyLength) bytes"
            )
        }
        guard oprfSeed.count == 32 else {
            throw OpaqueError.invalidInput("OPRF seed must be 32 bytes")
        }

        var rawHandle: UnsafeMutableRawPointer?
        let result = privateKey.withUnsafeBytes { skPtr in
            publicKey.withUnsafeBytes { pkPtr in
                oprfSeed.withUnsafeBytes { seedPtr in
                    opaque_relay_create_with_keys(
                        skPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        privateKey.count,
                        pkPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        publicKey.count,
                        seedPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        oprfSeed.count,
                        &rawHandle
                    )
                }
            }
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
            opaque_relay_destroy(UnsafeMutableRawPointer(h))
        }
    }

    public func createState() throws -> RelayState {
        try RelayState()
    }

    public func createRegistrationResponse(request: Data, accountId: Data) throws -> Data {
        lock.lock()
        defer { lock.unlock() }

        guard let handle = handle else {
            throw OpaqueError.invalidState
        }

        guard request.count == OpaqueAgent.Constants.registrationRequestLength else {
            throw OpaqueError.invalidInput(
                "Request must be \(OpaqueAgent.Constants.registrationRequestLength) bytes"
            )
        }

        var response = Data(count: OpaqueAgent.Constants.registrationResponseLength)

        let result = request.withUnsafeBytes { reqPtr in
            accountId.withUnsafeBytes { aidPtr in
                response.withUnsafeMutableBytes { respPtr in
                    opaque_relay_create_registration_response(
                        UnsafeRawPointer(handle),
                        reqPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        request.count,
                        aidPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        accountId.count,
                        respPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        OpaqueAgent.Constants.registrationResponseLength
                    )
                }
            }
        }

        guard result == 0 else {
            throw OpaqueError.fromCode(result)
        }

        return response
    }

    public static func buildCredentials(record: Data) throws -> Data {
        guard record.count >= OpaqueAgent.Constants.registrationRecordLength else {
            throw OpaqueError.invalidInput(
                "Record must be at least \(OpaqueAgent.Constants.registrationRecordLength) bytes"
            )
        }

        let credentialsLength = OpaqueAgent.Constants.registrationRecordLength
        var credentials = Data(count: credentialsLength)

        let result = record.withUnsafeBytes { recPtr in
            credentials.withUnsafeMutableBytes { credPtr in
                opaque_relay_build_credentials(
                    recPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    record.count,
                    credPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    credentialsLength
                )
            }
        }

        guard result == 0 else {
            throw OpaqueError.fromCode(result)
        }

        return credentials
    }

    public func generateKE2(
        ke1: Data,
        accountId: Data,
        credentials: Data,
        state: RelayState
    ) throws -> Data {
        lock.lock()
        defer { lock.unlock() }

        guard let handle = handle else {
            throw OpaqueError.invalidState
        }

        guard ke1.count == OpaqueAgent.Constants.ke1Length else {
            throw OpaqueError.invalidInput(
                "KE1 must be \(OpaqueAgent.Constants.ke1Length) bytes"
            )
        }

        var ke2 = Data(count: OpaqueAgent.Constants.ke2Length)

        let result = try state.withHandle { stateHandle in
            ke1.withUnsafeBytes { ke1Ptr in
                accountId.withUnsafeBytes { aidPtr in
                    credentials.withUnsafeBytes { credPtr in
                        ke2.withUnsafeMutableBytes { ke2Ptr in
                            opaque_relay_generate_ke2(
                                UnsafeRawPointer(handle),
                                ke1Ptr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                ke1.count,
                                aidPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                accountId.count,
                                credPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                credentials.count,
                                ke2Ptr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                OpaqueAgent.Constants.ke2Length,
                                stateHandle
                            )
                        }
                    }
                }
            }
        }

        guard result == 0 else {
            throw OpaqueError.fromCode(result)
        }

        return ke2
    }

    public func finish(ke3: Data, state: RelayState) throws -> AuthenticationKeys {
        lock.lock()
        defer { lock.unlock() }

        guard let handle = handle else {
            throw OpaqueError.invalidState
        }

        guard ke3.count == OpaqueAgent.Constants.ke3Length else {
            throw OpaqueError.invalidInput(
                "KE3 must be \(OpaqueAgent.Constants.ke3Length) bytes"
            )
        }

        var sessionKey = Data(count: OpaqueAgent.Constants.sessionKeyLength)
        var masterKey = Data(count: OpaqueAgent.Constants.masterKeyLength)

        let result = try state.withHandle { stateHandle in
            ke3.withUnsafeBytes { ke3Ptr in
                sessionKey.withUnsafeMutableBytes { skPtr in
                    masterKey.withUnsafeMutableBytes { mkPtr in
                        opaque_relay_finish(
                            UnsafeRawPointer(handle),
                            ke3Ptr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            ke3.count,
                            stateHandle,
                            skPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            OpaqueAgent.Constants.sessionKeyLength,
                            mkPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            OpaqueAgent.Constants.masterKeyLength
                        )
                    }
                }
            }
        }

        guard result == 0 else {
            throw OpaqueError.fromCode(result)
        }

        return AuthenticationKeys(sessionKey: sessionKey, masterKey: masterKey)
    }
}

extension OpaqueRelay {
    public final class KeyPair: @unchecked Sendable {
        internal let handle: OpaquePointer

        public static func generate() throws -> KeyPair {
            var rawHandle: UnsafeMutableRawPointer?
            let result = opaque_relay_keypair_generate(&rawHandle)

            guard result == 0, let validHandle = rawHandle else {
                throw OpaqueError.fromCode(result)
            }

            return KeyPair(handle: OpaquePointer(validHandle))
        }

        private init(handle: OpaquePointer) {
            self.handle = handle
        }

        deinit {
            opaque_relay_keypair_destroy(UnsafeMutableRawPointer(handle))
        }

        public func oprfSeed() throws -> Data {
            let seedLength = 32
            var seed = Data(count: seedLength)

            let result = seed.withUnsafeMutableBytes { seedPtr in
                opaque_relay_keypair_get_oprf_seed(
                    UnsafeMutableRawPointer(handle),
                    seedPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    seedLength
                )
            }

            guard result == 0 else {
                throw OpaqueError.fromCode(result)
            }

            return seed
        }

        public func publicKey() throws -> Data {
            var pk = Data(count: OpaqueAgent.Constants.publicKeyLength)

            let result = pk.withUnsafeMutableBytes { pkPtr in
                opaque_relay_keypair_get_public_key(
                    UnsafeMutableRawPointer(handle),
                    pkPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    OpaqueAgent.Constants.publicKeyLength
                )
            }

            guard result == 0 else {
                throw OpaqueError.fromCode(result)
            }

            return pk
        }
    }
}

extension OpaqueRelay {
    public final class RelayState: @unchecked Sendable {
        private var handle: OpaquePointer?
        private let lock = NSLock()

        internal init() throws {
            var rawHandle: UnsafeMutableRawPointer?
            let result = opaque_relay_state_create(&rawHandle)

            guard result == 0, let validHandle = rawHandle else {
                throw OpaqueError.fromCode(result)
            }

            self.handle = OpaquePointer(validHandle)
        }

        internal func withHandle<T>(_ body: (UnsafeRawPointer) throws -> T) throws -> T {
            lock.lock()
            defer { lock.unlock() }
            guard let h = handle else {
                throw OpaqueError.invalidState
            }
            return try body(UnsafeRawPointer(h))
        }

        public func dispose() {
            lock.lock()
            let h = handle
            handle = nil
            lock.unlock()
            if let h {
                opaque_relay_state_destroy(UnsafeMutableRawPointer(h))
            }
        }

        deinit { dispose() }
    }
}
