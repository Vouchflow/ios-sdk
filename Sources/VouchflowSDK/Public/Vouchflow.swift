import Foundation

/// The main entry point for the Vouchflow SDK.
///
/// ## Setup
/// Call `configure(_:)` once at app startup, before any other SDK method:
/// ```swift
/// try Vouchflow.configure(VouchflowConfig(apiKey: "vsk_live_...", environment: .production))
/// ```
///
/// ## Verification
/// ```swift
/// do {
///     let result = try await Vouchflow.shared.verify(context: .signup)
///     // result.verified, result.confidence, result.deviceToken, result.signals
/// } catch VouchflowError.biometricCancelled(let sessionId) {
///     // Show retry button
/// } catch VouchflowError.biometricFailed(let sessionId) {
///     let fallback = try await Vouchflow.shared.requestFallback(
///         sessionId: sessionId,
///         email: userEmail,
///         reason: .biometricFailed
///     )
///     // Show OTP input
/// }
/// ```
///
/// ## Fallback OTP submission
/// ```swift
/// let result = try await Vouchflow.shared.submitFallbackOTP(
///     sessionId: fallback.fallbackSessionId,
///     otp: userEnteredCode
/// )
/// ```
public final class Vouchflow {

    /// The shared SDK instance. Access only after calling `configure(_:)`.
    public static let shared = Vouchflow()

    private static let lock = NSLock()
    private static var _config: VouchflowConfig?

    private var verificationManager: VerificationManager?
    private var fallbackManager: FallbackManager?

    private init() {}

    // MARK: - Configuration

    /// Configures the SDK. Must be called once before any other SDK method, typically in
    /// `application(_:didFinishLaunchingWithOptions:)` or the SwiftUI `App.init`.
    ///
    /// - Throws: `VouchflowError.invalidAPIKey` if the key does not match the `vsk_` prefix format.
    public static func configure(_ config: VouchflowConfig) throws {
        guard config.apiKey.hasPrefix("vsk_") else {
            throw VouchflowError.invalidAPIKey
        }

        lock.withLock {
            _config = config
            let keychain = KeychainManager(accessGroup: config.keychainAccessGroup)
            let apiClient = VouchflowAPIClient(config: config)
            let keyManager = SecureEnclaveKeyManager()
            let challengeProcessor = ChallengeProcessor()
            let sessionCache = SessionCache()
            let enrollmentManager = EnrollmentManager(
                config: config,
                keychainManager: keychain,
                keyManager: keyManager,
                attestationProvider: AttestationProvider(),
                apiClient: apiClient
            )
            shared.verificationManager = VerificationManager(
                config: config,
                keychainManager: keychain,
                keyManager: keyManager,
                challengeProcessor: challengeProcessor,
                sessionCache: sessionCache,
                enrollmentManager: enrollmentManager,
                apiClient: apiClient
            )
            shared.fallbackManager = FallbackManager(
                keychainManager: keychain,
                apiClient: apiClient
            )
        }
    }

    // MARK: - Verification

    /// Verifies the current device. Handles enrollment, biometric presentation, and challenge
    /// signing transparently. The developer needs only one call for the happy path.
    ///
    /// - Parameters:
    ///   - context: The action being verified (signup, login, sensitive_action).
    ///   - minimumConfidence: If the device cannot reach this confidence level, throws
    ///     `VouchflowError.minimumConfidenceUnmet` instead of initiating fallback.
    /// - Returns: A `VouchflowResult` on success.
    /// - Throws: `VouchflowError`
    public func verify(
        context: VerificationContext,
        minimumConfidence: Confidence? = nil
    ) async throws -> VouchflowResult {
        guard let manager = verificationManager else {
            throw VouchflowError.notConfigured
        }
        return try await manager.verify(context: context, minimumConfidence: minimumConfidence)
    }

    // MARK: - Fallback

    /// Initiates email OTP fallback for a verification session.
    ///
    /// Call this after catching `biometricFailed` or `biometricCancelled`. The SDK hashes
    /// the email with SHA-256 internally — do not pre-hash it.
    ///
    /// - Parameters:
    ///   - sessionId: The session ID from the thrown `VouchflowError` associated value.
    ///   - email: The user's plain-text email address. Never stored or logged by the SDK.
    ///   - reason: Why fallback is being requested.
    /// - Returns: A `FallbackResult` containing the `fallbackSessionId` and OTP expiry.
    public func requestFallback(
        sessionId: String,
        email: String,
        reason: FallbackReason = .biometricFailed
    ) async throws -> FallbackResult {
        guard let manager = fallbackManager else {
            throw VouchflowError.notConfigured
        }
        return try await manager.requestFallback(
            sessionId: sessionId,
            email: email,
            reason: reason
        )
    }

    /// Submits the OTP entered by the user to complete a fallback verification.
    ///
    /// - Parameters:
    ///   - sessionId: The `fallbackSessionId` from the `FallbackResult` returned by `requestFallback`.
    ///   - otp: The 6-digit code entered by the user.
    /// - Returns: A `FallbackVerificationResult` with `confidence: .low`.
    public func submitFallbackOTP(
        sessionId: String,
        otp: String
    ) async throws -> FallbackVerificationResult {
        guard let manager = fallbackManager else {
            throw VouchflowError.notConfigured
        }
        return try await manager.submitOTP(sessionId: sessionId, otp: otp)
    }
}
