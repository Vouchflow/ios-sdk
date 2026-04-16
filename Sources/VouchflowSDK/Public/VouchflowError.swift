import Foundation

/// All errors surfaced to the developer by the Vouchflow SDK.
///
/// The SDK throws rather than using delegate callbacks or result types — the developer
/// catches what they care about and lets everything else propagate.
public enum VouchflowError: Error {

    // MARK: - Configuration

    /// `Vouchflow.configure(_:)` was not called before using the SDK.
    case notConfigured

    /// The API key provided to `VouchflowConfig` is not a recognised Vouchflow key.
    case invalidAPIKey

    // MARK: - Enrollment

    /// Device enrollment failed. The SDK will retry automatically on the next app launch.
    /// Verification can still proceed — the developer may choose to surface a degraded
    /// experience or hard-fail based on their use case.
    case enrollmentFailed(underlying: Error?)

    /// App Attest is not supported on this device or has not been configured.
    /// Enrollment continues without attestation; confidence ceiling is set to `medium`.
    case attestationUnavailable

    /// The SDK could not read from or write to the Keychain.
    /// This typically means the device is locked and has never been unlocked since boot.
    case keychainAccessDenied

    // MARK: - Biometric

    /// Face ID / Touch ID is not enrolled or not available on this device.
    case biometricUnavailable

    /// The user explicitly cancelled the biometric prompt.
    /// Provide a retry button. Call `requestFallback(sessionId:email:reason:)` if the user
    /// opts into email fallback instead.
    ///
    /// - Parameter sessionId: Pass to `requestFallback(sessionId:email:reason:)` to initiate
    ///   email fallback for this verification session.
    case biometricCancelled(sessionId: String)

    /// The biometric attempt failed (wrong face / finger, lockout, hardware error).
    /// Do not auto-retry more than once. Offer fallback or hard-fail.
    ///
    /// - Parameter sessionId: Pass to `requestFallback(sessionId:email:reason:)` to initiate
    ///   email fallback for this verification session.
    case biometricFailed(sessionId: String)

    // MARK: - Session

    /// The verification session expired before the challenge was signed.
    /// The SDK automatically retries once using the server-provided retry session.
    /// This error is thrown only when the retry session also expires.
    case sessionExpiredRepeatedly

    /// `requestFallback` was called but there is no active session to fall back from.
    /// Call `verify` first; only call `requestFallback` after catching `biometricCancelled`
    /// or `biometricFailed`.
    case noActiveSession

    // MARK: - Confidence

    /// The device cannot meet the `minimumConfidence` threshold specified in `verify(context:minimumConfidence:)`.
    case minimumConfidenceUnmet

    // MARK: - Network

    /// A network connection could not be established.
    case networkUnavailable

    /// The Vouchflow API returned an unexpected error response.
    case serverError(statusCode: Int, code: String?, message: String?)

    /// The server's TLS certificate did not match the configured pins.
    /// This may indicate a MITM attack or a pin rotation that was not deployed to the SDK.
    case pinningFailure
}
