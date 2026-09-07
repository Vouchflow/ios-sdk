import Foundation
import CryptoKit

/// Manages the email OTP and reviewer-code fallback paths.
///
/// Called by the developer after catching `biometricFailed` or `biometricCancelled`
/// from `verify()`. The developer decides whether to offer fallback — the SDK never
/// auto-triggers it.
final class FallbackManager {

    private let keychainManager: KeychainBackend
    private let apiClient: VouchflowAPIClient

    init(keychainManager: KeychainBackend, apiClient: VouchflowAPIClient) {
        self.keychainManager = keychainManager
        self.apiClient = apiClient
    }

    // MARK: - Initiate fallback

    /// Initiates email OTP fallback for the given verification session.
    ///
    /// The SDK SHA-256 hashes the email for rate limiting. The server also needs the plaintext
    /// email to deliver the OTP. Neither value is stored beyond the request.
    func requestFallback(
        sessionId: String,
        email: String,
        reason: FallbackReason
    ) async throws -> FallbackResult {
        let deviceToken = try? keychainManager.read(key: KeychainKey.deviceToken)
        let emailHash = sha256Hex(email)

        let request = FallbackRequest(
            deviceToken: deviceToken,
            email: email,
            emailHash: emailHash,
            reason: reason.rawValue
        )
        let response = try await apiClient.initiateFallback(sessionId: sessionId, request)

        return FallbackResult(
            fallbackSessionId: response.fallbackSessionId,
            expiresAt: response.expiresAt
        )
    }

    // MARK: - Submit OTP

    /// Submits the 6-digit OTP entered by the user.
    ///
    /// Uses `fallbackSessionId` from `FallbackResult` as the path parameter (same
    /// `/v1/verify/{id}/complete` endpoint, keyed by the fallback session rather than the
    /// original session).
    func submitOTP(sessionId: String, otp: String) async throws -> FallbackVerificationResult {
        let deviceToken = try? keychainManager.read(key: KeychainKey.deviceToken)
        let request = FallbackCompleteRequest(otp: otp, deviceToken: deviceToken)
        let response = try await apiClient.completeFallback(fallbackSessionId: sessionId, request)

        return mapResult(response)
    }

    /// Completes fallback in one request, without email or OTP delivery.
    func requestFallback(sessionId: String, reviewerCode: String) async throws -> FallbackVerificationResult {
        guard let deviceToken = try keychainManager.read(key: KeychainKey.deviceToken) else {
            throw VouchflowError.enrollmentFailed(underlying: nil)
        }
        let request = FallbackRequest.reviewerCode(deviceToken: deviceToken, code: reviewerCode)
        let response = try await apiClient.acceptReviewerCode(sessionId: sessionId, request)
        return mapResult(response)
    }

    private func mapResult(_ response: FallbackCompleteResponse) -> FallbackVerificationResult {
        FallbackVerificationResult(
            verified: response.verified,
            confidence: Confidence(rawValue: response.confidence) ?? .low,
            sessionState: response.sessionState,
            fallbackSignals: response.fallbackSignals.map { signals in
                FallbackSignals(
                    ipConsistent: signals.ipConsistent,
                    disposableEmailDomain: signals.disposableEmailDomain,
                    deviceHasPriorVerifications: signals.deviceHasPriorVerifications,
                    emailDomainAgeDays: signals.emailDomainAgeDays,
                    otpAttempts: signals.otpAttempts,
                    timeToCompleteSeconds: signals.timeToCompleteSeconds
                )
            }
        )
    }

    // MARK: - Helpers

    private func sha256Hex(_ input: String) -> String {
        let normalized = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let digest = SHA256.hash(data: Data(normalized.utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
