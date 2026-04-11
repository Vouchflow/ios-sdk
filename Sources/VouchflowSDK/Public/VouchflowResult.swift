import Foundation

// MARK: - Supporting types

/// Confidence level returned by a completed verification.
public enum Confidence: String, Decodable, Equatable {
    case high
    case medium
    case low
}

/// The action the user is performing when `verify()` is called.
public enum VerificationContext: String, Encodable {
    case signup
    case login
    case sensitiveAction = "sensitive_action"
}

/// The reason passed to `requestFallback(sessionId:email:reason:)`.
public enum FallbackReason: String, Encodable {
    case attestationUnavailable = "attestation_unavailable"
    case attestationFailed = "attestation_failed"
    case attestationTimeout = "attestation_timeout"
    case biometricUnavailable = "biometric_unavailable"
    case biometricFailed = "biometric_failed"
    case biometricCancelled = "biometric_cancelled"
    case keyInvalidated = "key_invalidated"
    case sdkError = "sdk_error"
    case minimumConfidenceUnmet = "minimum_confidence_unmet"
    case developerInitiated = "developer_initiated"
    case enrollmentFailed = "enrollment_failed"
}

// MARK: - Signals

/// Device signals included in a completed verification.
public struct VouchflowSignals {
    /// The device token survived app deletion and reinstall (Keychain persistence confirmed).
    public let keychainPersistent: Bool
    /// Biometric authentication (Face ID / Touch ID) was used for this verification.
    public let biometricUsed: Bool
    /// This device has verified across more than one Vouchflow-integrated app.
    public let crossAppHistory: Bool
    /// Anomaly flags raised against this device in the network graph. Empty for clean devices.
    public let anomalyFlags: [String]
    /// App Attest was verified at enrollment time for this device.
    public let attestationVerified: Bool
}

// MARK: - Results

/// The result of a successful primary verification.
public struct VouchflowResult {
    /// Whether the verification was successful.
    public let verified: Bool
    /// Confidence level of this verification.
    public let confidence: Confidence
    /// The device token for this device. Use this for server-side reputation API calls
    /// (`GET /v1/device/{device_token}/reputation`). Never log or store it unnecessarily.
    public let deviceToken: String
    /// Number of days since this device token was first enrolled.
    public let deviceAgeDays: Int
    /// Total verifications for this device in the Vouchflow network (across all network-participating apps).
    public let networkVerifications: Int
    /// When this device was first seen by Vouchflow.
    public let firstSeen: Date?
    /// Device signals for this verification.
    public let signals: VouchflowSignals
    /// Whether email fallback was used (always `false` for `VouchflowResult` — fallback returns `FallbackVerificationResult`).
    public let fallbackUsed: Bool
    /// The context passed to `verify(context:)`.
    public let context: VerificationContext
}

/// The result of a successful fallback (email OTP) verification.
public struct FallbackVerificationResult {
    /// Whether the OTP verification was successful.
    public let verified: Bool
    /// Always `.low` for fallback — email OTP proves inbox access, not device presence.
    public let confidence: Confidence
    /// Session state at completion.
    public let sessionState: String
    /// Signals available from fallback (no device cryptography involved).
    public let fallbackSignals: FallbackSignals
}

/// Signals returned when a fallback (email OTP) verification completes.
public struct FallbackSignals {
    /// Whether the OTP submission came from the same IP that initiated the session.
    public let ipConsistent: Bool
    /// Whether the email domain is a known disposable provider.
    public let disposableEmailDomain: Bool
    /// Whether this device has prior successful verifications.
    public let deviceHasPriorVerifications: Bool
    /// Age of the email domain in days. `nil` if the domain age could not be determined.
    public let emailDomainAgeDays: Int?
    /// Number of OTP attempts made.
    public let otpAttempts: Int
    /// Seconds from fallback initiation to OTP submission.
    public let timeToCompleteSeconds: Int
}

/// Returned by `requestFallback(sessionId:email:reason:)`.
/// Pass `fallbackSessionId` to `submitFallbackOTP(sessionId:otp:)`.
public struct FallbackResult {
    /// Identifier for this fallback session. Pass to `submitFallbackOTP(sessionId:otp:)`.
    public let fallbackSessionId: String
    /// When the OTP expires. 5-minute window from initiation.
    public let expiresAt: Date
}
