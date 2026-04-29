import Foundation
import LocalAuthentication

/// Orchestrates the complete verification flow.
///
/// ## Happy path
/// 1. `EnrollmentManager.ensureEnrolled()` — no-op if already enrolled
/// 2. `POST /v1/verify` → session_id + challenge
/// 3. `LAContext.evaluatePolicy` → biometric
/// 4. `ChallengeProcessor.sign` → signed_challenge
/// 5. `POST /v1/verify/{id}/complete` → `VouchflowResult`
///
/// ## Session expiry handling
/// If the session expires while the app is backgrounded:
/// - First expiry: use `retry_session_id` + `retry_challenge` from the 410 response.
/// - Second expiry: throw `sessionExpiredRepeatedly`.
///
/// ## Backgrounding during biometric
/// `LAError.appCancel` means iOS sent the app to the background. The SDK waits for
/// foreground via `SessionManager.waitForForeground()` and silently re-presents the
/// biometric prompt. The session expiry loop handles the case where the session times out
/// while waiting.
final class VerificationManager {

    private let config: VouchflowConfig
    private let keychainManager: KeychainManager
    private let keyManager: SecureEnclaveKeyManager
    private let challengeProcessor: ChallengeProcessor
    private let sessionCache: SessionCache
    private let enrollmentManager: EnrollmentManager
    private let apiClient: VouchflowAPIClient

    /// The session ID from the most recently initiated (but not yet completed) verification.
    /// Set when a session is created, updated on retry, cleared on successful completion.
    /// Retained through biometric failures so `Vouchflow.requestFallback` can use it without
    /// the developer having to extract and pass it from the thrown error.
    private(set) var pendingFallbackSessionId: String?

    init(
        config: VouchflowConfig,
        keychainManager: KeychainManager,
        keyManager: SecureEnclaveKeyManager,
        challengeProcessor: ChallengeProcessor,
        sessionCache: SessionCache,
        enrollmentManager: EnrollmentManager,
        apiClient: VouchflowAPIClient
    ) {
        self.config = config
        self.keychainManager = keychainManager
        self.keyManager = keyManager
        self.challengeProcessor = challengeProcessor
        self.sessionCache = sessionCache
        self.enrollmentManager = enrollmentManager
        self.apiClient = apiClient
    }

    // MARK: - Reset

    /// Clears all local enrollment data. Called by `Vouchflow.reset()`.
    func reset() {
        try? keyManager.deleteKey(from: keychainManager)
        try? keychainManager.delete(key: KeychainKey.deviceToken)
        try? keychainManager.delete(key: KeychainKey.pendingToken)
        pendingFallbackSessionId = nil
        sessionCache.clear()
        VouchflowLogger.debug("[VouchflowSDK] Reset complete — local enrollment data cleared.")
    }

    // MARK: - Test harness utilities

    /// Triggers enrollment if not already enrolled. For developer test harnesses only.
    /// On return, `cachedDeviceToken` will be non-nil if enrollment succeeded.
    func ensureEnrolledForTesting() async throws {
        try await enrollmentManager.ensureEnrolled()
    }

    // MARK: - Session initiation (test harness utility)

    /// Initiates a verify session on the server without biometric authentication.
    /// Sets `pendingFallbackSessionId` so `requestFallback` will work after this call.
    /// For use in developer test harnesses only — not for production app code.
    func initiateSession() async throws -> String {
        guard let deviceToken = try keychainManager.read(key: KeychainKey.deviceToken) else {
            throw VouchflowError.enrollmentFailed(underlying: nil)
        }
        let verifyRequest = VerifyRequest(
            deviceToken: deviceToken,
            context: VerificationContext.login.rawValue,
            minimumConfidence: nil
        )
        let sessionResponse = try await apiClient.initiateVerification(verifyRequest)
        pendingFallbackSessionId = sessionResponse.sessionId
        return sessionResponse.sessionId
    }

    // MARK: - Verify

    func verify(context: VerificationContext, minimumConfidence: Confidence?) async throws -> VouchflowResult {
        // Step 1: Ensure enrolled (actor-serialised, no-op if already enrolled)
        do {
            try await enrollmentManager.ensureEnrolled()
        } catch let error as VouchflowError {
            throw error
        } catch {
            throw VouchflowError.enrollmentFailed(underlying: error)
        }

        // Step 2: Read device token (must exist after ensureEnrolled)
        guard let deviceToken = try keychainManager.read(key: KeychainKey.deviceToken) else {
            throw VouchflowError.enrollmentFailed(underlying: nil)
        }

        // Step 3: Initiate session
        let verifyRequest = VerifyRequest(
            deviceToken: deviceToken,
            context: context.rawValue,
            minimumConfidence: minimumConfidence?.rawValue
        )
        var sessionResponse = try await apiClient.initiateVerification(verifyRequest)
        pendingFallbackSessionId = sessionResponse.sessionId

        sessionCache.store(SessionCache.CachedSession(
            sessionId: sessionResponse.sessionId,
            challenge: sessionResponse.challenge,
            expiresAt: sessionResponse.expiresAt,
            expiryCount: 0
        ))

        // Steps 4–5: Sign + submit loop, handles up to 2 consecutive session expirations
        var expiryCount = 0
        while expiryCount < 2 {
            // Sign the challenge (handles biometric presentation and backgrounding internally)
            let signedChallenge: String
            do {
                signedChallenge = try await signChallenge(
                    sessionResponse.challenge,
                    sessionId: sessionResponse.sessionId
                )
            } catch {
                // Biometric errors bubble directly — no retry at this level
                sessionCache.clear()
                throw error
            }

            // Submit
            let completeRequest = CompleteVerificationRequest(
                deviceToken: deviceToken,
                signedChallenge: signedChallenge,
                biometricUsed: true
            )
            do {
                let response = try await apiClient.completeVerification(
                    sessionId: sessionResponse.sessionId,
                    completeRequest
                )
                sessionCache.clear()
                pendingFallbackSessionId = nil // session fully resolved — no fallback possible
                return mapResult(response, deviceToken: deviceToken, context: context)

            } catch VouchflowError.__sessionExpiredInternal(let retryId, let retryChallenge) {
                // Session expired — use the server-provided retry session transparently
                expiryCount += 1
                VouchflowLogger.debug("[VouchflowSDK] Session expired (expiry #\(expiryCount)). Using retry session.")
                sessionResponse = VerifyResponse(
                    sessionId: retryId,
                    challenge: retryChallenge,
                    expiresAt: Date().addingTimeInterval(60),
                    sessionState: "INITIATED"
                )
                pendingFallbackSessionId = retryId // follow the retry chain
                sessionCache.store(SessionCache.CachedSession(
                    sessionId: retryId,
                    challenge: retryChallenge,
                    expiresAt: sessionResponse.expiresAt,
                    expiryCount: expiryCount
                ))
            }
        }

        sessionCache.clear()
        throw VouchflowError.sessionExpiredRepeatedly
    }

    // MARK: - Biometric

    /// Evaluates biometric policy and signs the challenge. Retries silently on app backgrounding.
    private func signChallenge(_ challengeBase64: String, sessionId: String) async throws -> String {
        guard let privateKey = try keyManager.loadKey(from: keychainManager) else {
            throw VouchflowError.enrollmentFailed(underlying: nil)
        }

        // Biometric loop: retries silently after LAError.appCancel (app backgrounded)
        while true {
            let laContext = LAContext()
            do {
                try await evaluateBiometric(context: laContext)
                break // success — proceed to signing
            } catch let error as LAError {
                switch error.code {
                case .appCancel, .systemCancel:
                    // App was sent to background mid-prompt. Wait for foreground and retry.
                    VouchflowLogger.debug("[VouchflowSDK] Biometric interrupted by app backgrounding. Waiting for foreground.")
                    await SessionManager.shared.waitForForeground()
                    // Continue the while loop — re-present biometric. If the session expired
                    // while backgrounded, the completeVerification call will return 410 and
                    // the outer expiry loop handles it.
                    continue

                case .userCancel:
                    throw VouchflowError.biometricCancelled(sessionId: sessionId)

                case .passcodeNotSet:
                    // Device has neither biometrics nor a passcode configured — cannot authenticate.
                    throw VouchflowError.biometricUnavailable

                case .biometryNotAvailable, .biometryNotEnrolled, .biometryLockout:
                    // With .deviceOwnerAuthentication, iOS falls back to passcode automatically,
                    // so these cases are rare. Treat as failed rather than unavailable so the
                    // user can retry (the passcode path may still be available).
                    throw VouchflowError.biometricFailed(sessionId: sessionId)

                default:
                    throw VouchflowError.biometricFailed(sessionId: sessionId)
                }
            }
        }

        return try challengeProcessor.sign(challengeBase64: challengeBase64, with: privateKey)
    }

    /// Async wrapper for `LAContext.evaluatePolicy` (native async API requires iOS 16).
    ///
    /// Uses `.deviceOwnerAuthentication` so the user can authenticate with Face ID, Touch ID,
    /// or the device passcode — iOS presents passcode automatically if biometrics are unavailable
    /// or fail. This avoids hard-blocking users who have a passcode but no biometric enrolled.
    private func evaluateBiometric(context: LAContext) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            context.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: "Verify your identity"
            ) { success, error in
                if success {
                    continuation.resume()
                } else {
                    continuation.resume(throwing: error!)
                }
            }
        }
    }

    // MARK: - Result mapping

    private func mapResult(
        _ response: CompleteVerificationResponse,
        deviceToken: String,
        context: VerificationContext
    ) -> VouchflowResult {
        VouchflowResult(
            verified: response.verified,
            confidence: response.confidence.flatMap { Confidence(rawValue: $0) } ?? .low,
            deviceToken: deviceToken,
            deviceAgeDays: response.deviceAgeDays,
            networkVerifications: response.networkVerifications,
            firstSeen: response.firstSeen,
            signals: VouchflowSignals(
                keychainPersistent: response.signals.keychainPersistent,
                biometricUsed: response.signals.biometricUsed,
                crossAppHistory: response.signals.crossAppHistory,
                anomalyFlags: response.signals.anomalyFlags,
                attestationVerified: response.signals.attestationVerified
            ),
            fallbackUsed: response.fallbackUsed,
            context: context
        )
    }
}
