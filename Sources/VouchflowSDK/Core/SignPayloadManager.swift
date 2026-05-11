import Foundation
import CryptoKit
import LocalAuthentication

/// Drives the `signPayload` ceremony per the signPayload RFC §4.2.
///
/// Flow per call:
///   1. Canonicalize payload (RFC 8785 JCS) → bytes
///   2. POST /v1/sign  → server returns 32-byte challenge bound to the payload
///   3. signing_input = canonical_payload || challenge
///   4. Gate biometric via LAContext (same path as VerificationManager)
///   5. SE key signs signing_input (CryptoKit applies SHA-256 internally)
///   6. If minConfidence == .high, generate an App Attest assertion over
///      SHA-256(signing_input) using the keyId persisted at enrollment
///   7. POST /v1/sign/:session_id/complete → server returns the JWS bundle
final class SignPayloadManager {

    private let config: VouchflowConfig
    private let keychainManager: KeychainManager
    private let keyManager: SecureEnclaveKeyManager
    private let attestationProvider: AttestationProvider
    private let enrollmentManager: EnrollmentManager
    private let apiClient: VouchflowAPIClient

    init(
        config: VouchflowConfig,
        keychainManager: KeychainManager,
        keyManager: SecureEnclaveKeyManager,
        attestationProvider: AttestationProvider,
        enrollmentManager: EnrollmentManager,
        apiClient: VouchflowAPIClient
    ) {
        self.config = config
        self.keychainManager = keychainManager
        self.keyManager = keyManager
        self.attestationProvider = attestationProvider
        self.enrollmentManager = enrollmentManager
        self.apiClient = apiClient
    }

    /// Sign an `Encodable` payload. See `Vouchflow.signPayload(...)` for docs.
    func signPayload<T: Encodable>(
        payload: T,
        context: String,
        minimumConfidence: Confidence
    ) async throws -> SignedBundle {
        // Canonicalize first — fast, deterministic, no I/O.
        let canonical: String
        do {
            canonical = try JCSCanonicalizer.canonicalize(payload)
        } catch {
            throw VouchflowError.canonicalizationFailed(underlying: error)
        }
        return try await signCanonicalized(
            canonicalized: canonical,
            context: context,
            minimumConfidence: minimumConfidence
        )
    }

    /// Internal entry for callers that have already canonicalized (used by
    /// tests and the harness). Production callers should use `signPayload`.
    func signCanonicalized(
        canonicalized: String,
        context: String,
        minimumConfidence: Confidence
    ) async throws -> SignedBundle {
        // Auto-enroll on first call if the device hasn't been enrolled yet,
        // mirroring VerificationManager.verify().
        try await enrollmentManager.ensureEnrolled()

        guard let deviceToken: String = try keychainManager.read(key: KeychainKey.deviceToken) else {
            throw VouchflowError.enrollmentFailed(underlying: nil)
        }
        guard let privateKey = try keyManager.loadKey(from: keychainManager) else {
            throw VouchflowError.enrollmentFailed(underlying: nil)
        }

        // 1. Initiate sign session
        let idempotencyKey = "sk_\(UUID().uuidString.lowercased().replacingOccurrences(of: "-", with: ""))"
        let initRequest = SignInitiateRequest(
            deviceToken: deviceToken,
            context: context,
            canonicalizedPayload: canonicalized,
            minimumConfidence: minimumConfidence.rawValue,
            idempotencyKey: idempotencyKey
        )
        let initResponse: SignInitiateResponse
        do {
            initResponse = try await apiClient.initiateSign(initRequest)
        } catch let vfError as VouchflowError {
            // Surface server-side rejections directly (e.g., minimum_confidence_unmet).
            throw vfError
        }

        // 2. Build signing_input = canonical_payload || challenge.
        //    CryptoKit's signature(for:) applies SHA-256 internally.
        guard let canonicalBytes = canonicalized.data(using: .utf8) else {
            throw VouchflowError.canonicalizationFailed(underlying: nil)
        }
        guard let challengeBytes = Data(base64Encoded: initResponse.challenge) else {
            throw VouchflowError.serverError(
                statusCode: 200,
                code: "invalid_challenge",
                message: "Server returned a non-base64 challenge."
            )
        }
        var signingInput = Data()
        signingInput.append(canonicalBytes)
        signingInput.append(challengeBytes)

        // 3. Biometric gate (same shape as VerificationManager.signChallenge)
        try await evaluateBiometric()

        // 4. SE signature over signing_input
        let signature: P256.Signing.ECDSASignature
        do {
            signature = try privateKey.signature(for: signingInput)
        } catch {
            throw VouchflowError.payloadSignatureRejected
        }

        // 5. Optional App Attest re-attestation for the high-confidence path
        var appAttestAssertionB64: String?
        if minimumConfidence == .high {
            // Apple expects clientDataHash to be SHA-256 of "client data". We
            // use SHA-256(signing_input) — ties the assertion to the same
            // payload+challenge the SE signature is over.
            let clientDataHash = Data(SHA256.hash(data: signingInput))
            if let keyId: String = try? keychainManager.read(key: KeychainKey.appAttestKeyId) {
                do {
                    appAttestAssertionB64 = try await attestationProvider.generateAssertion(
                        keyId: keyId,
                        clientDataHash: clientDataHash
                    )
                } catch {
                    // Non-fatal: server will cap confidence to medium if the
                    // assertion is absent. Surface as a warning rather than
                    // failing the call — caller can retry if they need high.
                    VouchflowLogger.warn(
                        "[VouchflowSDK] App Attest generateAssertion failed; confidence will cap at medium. Error: \(error)"
                    )
                    appAttestAssertionB64 = nil
                }
            }
        }

        // 6. Complete the session
        let completeRequest = SignCompleteRequest(
            deviceToken: deviceToken,
            signedChallenge: signature.derRepresentation.base64EncodedString(),
            appAttestAssertion: appAttestAssertionB64
        )
        let response: SignCompleteResponse = try await apiClient.completeSign(
            sessionId: initResponse.sessionId,
            completeRequest
        )

        // 7. Enforce minimumConfidence client-side as defense in depth.
        let achieved = Confidence(rawValue: response.confidence) ?? .medium
        if achieved.rank < minimumConfidence.rank {
            throw VouchflowError.minimumConfidenceUnmet
        }

        return SignedBundle(
            payload: canonicalized,
            context: context,
            assertion: response.assertion,
            signingDeviceId: response.signingDeviceId,
            deviceToken: response.deviceToken,
            confidence: achieved,
            signedAt: response.signedAt,
            platform: response.platform
        )
    }

    // MARK: - Biometric (mirrors VerificationManager.evaluateBiometric)

    private func evaluateBiometric() async throws {
        let context = LAContext()
        var canEvalErr: NSError?
        if !context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &canEvalErr) {
            throw VouchflowError.biometricUnavailable
        }
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            context.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: "Authorize this signature"
            ) { success, error in
                if success {
                    cont.resume()
                } else if let err = error as? LAError {
                    switch err.code {
                    case .userCancel:
                        cont.resume(throwing: VouchflowError.biometricCancelled(sessionId: ""))
                    case .passcodeNotSet, .biometryNotAvailable, .biometryNotEnrolled:
                        cont.resume(throwing: VouchflowError.biometricUnavailable)
                    default:
                        cont.resume(throwing: VouchflowError.biometricFailed(sessionId: ""))
                    }
                } else {
                    cont.resume(throwing: VouchflowError.biometricFailed(sessionId: ""))
                }
            }
        }
    }
}

// MARK: - Confidence ordering helper

private extension Confidence {
    var rank: Int {
        switch self {
        case .low: return 0
        case .medium: return 1
        case .high: return 2
        }
    }
}
