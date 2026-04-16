import Foundation

/// Detects enrollment state and performs enrollment atomically.
///
/// Uses Swift actor isolation to serialise concurrent enroll calls — if two `verify()` calls
/// race on a fresh install, only one enrollment network request is made.
///
/// ## Enrollment state machine
/// ```
/// FRESH_ENROLLMENT  → no device_token, no SE key → enroll from scratch
/// SKIP_ENROLLMENT   → device_token exists, SE key exists → nothing to do
/// REINSTALL         → device_token exists, no SE key → re-enroll with existing token
/// CORRUPTED         → no device_token, SE key exists → delete orphan key, enroll from scratch
/// ```
///
/// ## Atomicity
/// 1. Generate SE keypair
/// 2. Write pending placeholder to Keychain (`pending_dvt_<idempotencyKey>`)
/// 3. Obtain App Attest token
/// 4. POST /v1/enroll
/// 5a. Success → write real device_token, clear pending placeholder
/// 5b. Failure → leave placeholder in Keychain; retry on next `ensureEnrolled()` call
actor EnrollmentManager {

    private enum EnrollmentState {
        case skipEnrollment
        case freshEnrollment
        case reinstall(existingDeviceToken: String)
        case corrupted
    }

    private let config: VouchflowConfig
    private let keychainManager: KeychainManager
    private let keyManager: SecureEnclaveKeyManager
    private let attestationProvider: AttestationProvider
    private let apiClient: VouchflowAPIClient

    init(
        config: VouchflowConfig,
        keychainManager: KeychainManager,
        keyManager: SecureEnclaveKeyManager,
        attestationProvider: AttestationProvider,
        apiClient: VouchflowAPIClient
    ) {
        self.config = config
        self.keychainManager = keychainManager
        self.keyManager = keyManager
        self.attestationProvider = attestationProvider
        self.apiClient = apiClient
    }

    // MARK: - Public

    /// Ensures the device is enrolled. No-op if already enrolled. Idempotent — safe to call
    /// before every `verify()` call; returns immediately in the `SKIP_ENROLLMENT` case.
    func ensureEnrolled() async throws {
        // Check for a pending enrollment from a previous failed attempt and retry it.
        if let pendingToken = try readPendingToken() {
            try await retryPendingEnrollment(pendingToken: pendingToken)
            return
        }

        let state = try detectState()
        switch state {
        case .skipEnrollment:
            return

        case .freshEnrollment:
            try await performEnrollment(reason: "fresh_enrollment", existingDeviceToken: nil)

        case .reinstall(let existingToken):
            try await performEnrollment(reason: "reinstall", existingDeviceToken: existingToken)

        case .corrupted:
            VouchflowLogger.warn("[VouchflowSDK] Corrupted enrollment state detected — orphan SE key found with no device token. Re-enrolling from scratch.")
            try? keyManager.deleteKey(from: keychainManager)
            try await performEnrollment(reason: "fresh_enrollment", existingDeviceToken: nil)
        }
    }

    // MARK: - State detection

    private func detectState() throws -> EnrollmentState {
        let hasDeviceToken = try keychainManager.exists(key: KeychainKey.deviceToken)
        let hasKey = try keyManager.keyExists(in: keychainManager)

        switch (hasDeviceToken, hasKey) {
        case (true, true):  return .skipEnrollment
        case (false, false): return .freshEnrollment
        case (true, false):
            let token = try keychainManager.read(key: KeychainKey.deviceToken) ?? ""
            return .reinstall(existingDeviceToken: token)
        case (false, true): return .corrupted
        }
    }

    // MARK: - Enrollment

    private func performEnrollment(reason: String, existingDeviceToken: String?) async throws {
        let idempotencyKey = "ik_\(UUID().uuidString.lowercased())"

        // Step 1: Generate keypair in Secure Enclave
        let (privateKey, publicKeyBase64): (_, String)
        do {
            (privateKey, publicKeyBase64) = try keyManager.generateKeyPair()
        } catch {
            throw VouchflowError.enrollmentFailed(underlying: error)
        }

        // Step 2: Write placeholder before network call (crash safety)
        let placeholder = "pending_dvt_\(idempotencyKey)"
        do {
            try keychainManager.write(key: KeychainKey.pendingToken, value: placeholder)
            try keyManager.storeKey(privateKey, in: keychainManager)
        } catch let keychainError as KeychainError {
            throw keychainError.asVouchflowError
        }

        // Step 3: Obtain App Attest token (non-fatal on failure)
        let attestation: AttestationResult?
        do {
            attestation = try await attestationProvider.attest(enrollmentChallenge: idempotencyKey)
        } catch {
            VouchflowLogger.warn("[VouchflowSDK] App Attest failed — proceeding without attestation. confidence_ceiling will be medium. Error: \(error)")
            attestation = nil
        }

        // Step 4: POST /v1/enroll
        let attestationPayload = attestation.map {
            EnrollRequest.AttestationPayload(token: $0.token, keyId: $0.keyId)
        }
        let enrollRequest = EnrollRequest(
            idempotencyKey: idempotencyKey,
            platform: "ios",
            reason: reason,
            attestation: attestationPayload,
            publicKey: publicKeyBase64,
            deviceToken: existingDeviceToken
        )

        let response: EnrollResponse
        do {
            response = try await apiClient.enroll(enrollRequest)
        } catch {
            // Step 5b: Leave placeholder in Keychain — retried on next launch.
            VouchflowLogger.warn("[VouchflowSDK] Enrollment network call failed. Will retry on next launch. Error: \(error)")
            throw VouchflowError.enrollmentFailed(underlying: error)
        }

        // Step 5a: Commit real device token and clear placeholder
        do {
            try keychainManager.write(key: KeychainKey.deviceToken, value: response.deviceToken)
            try keychainManager.delete(key: KeychainKey.pendingToken)
        } catch let keychainError as KeychainError {
            throw keychainError.asVouchflowError
        }

        VouchflowLogger.debug("[VouchflowSDK] Enrollment complete. attestation_verified=\(response.attestationVerified), confidence_ceiling=\(response.confidenceCeiling)")
    }

    // MARK: - Pending enrollment retry

    private func readPendingToken() throws -> String? {
        try keychainManager.read(key: KeychainKey.pendingToken)
    }

    /// Retries a previously failed enrollment using the idempotency key stored in the placeholder.
    private func retryPendingEnrollment(pendingToken: String) async throws {
        let prefix = "pending_dvt_"
        guard pendingToken.hasPrefix(prefix) else {
            // Malformed placeholder — treat as fresh enrollment
            try? keychainManager.delete(key: KeychainKey.pendingToken)
            try await performEnrollment(reason: "fresh_enrollment", existingDeviceToken: nil)
            return
        }

        let idempotencyKey = String(pendingToken.dropFirst(prefix.count))

        // The keypair was already written in the previous attempt — reload it
        guard let privateKey = try keyManager.loadKey(from: keychainManager) else {
            // Key was lost alongside the placeholder — start fresh
            try? keychainManager.delete(key: KeychainKey.pendingToken)
            try await performEnrollment(reason: "fresh_enrollment", existingDeviceToken: nil)
            return
        }

        let existingDeviceToken = try keychainManager.read(key: KeychainKey.deviceToken)
        let reason = existingDeviceToken != nil ? "reinstall" : "fresh_enrollment"

        // Re-attest with the same idempotency key — the server's 24h idempotency window
        // will deduplicate if the first request actually succeeded.
        let attestation: AttestationResult?
        do {
            attestation = try await attestationProvider.attest(enrollmentChallenge: idempotencyKey)
        } catch {
            attestation = nil
        }

        let publicKeyBase64 = privateKey.publicKey.x963Representation.base64EncodedString()
        let attestationPayload = attestation.map {
            EnrollRequest.AttestationPayload(token: $0.token, keyId: $0.keyId)
        }
        let enrollRequest = EnrollRequest(
            idempotencyKey: idempotencyKey,
            platform: "ios",
            reason: reason,
            attestation: attestationPayload,
            publicKey: publicKeyBase64,
            deviceToken: existingDeviceToken
        )

        let response: EnrollResponse
        do {
            response = try await apiClient.enroll(enrollRequest)
        } catch {
            throw VouchflowError.enrollmentFailed(underlying: error)
        }

        do {
            try keychainManager.write(key: KeychainKey.deviceToken, value: response.deviceToken)
            try keychainManager.delete(key: KeychainKey.pendingToken)
        } catch let keychainError as KeychainError {
            throw keychainError.asVouchflowError
        }
    }
}
