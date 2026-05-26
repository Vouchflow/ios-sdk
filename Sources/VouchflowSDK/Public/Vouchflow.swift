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
/// } catch VouchflowError.biometricCancelled(_) {
///     // Show retry button
/// } catch VouchflowError.biometricFailed(_) {
///     let fallback = try await Vouchflow.shared.requestFallback(
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
    private var signPayloadManager: SignPayloadManager?
    private var keychainManager: KeychainBackend?

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
            let keychain: KeychainBackend = KeychainBackendFactory.make(config: config)
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
            shared.keychainManager = keychain
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
            shared.signPayloadManager = SignPayloadManager(
                config: config,
                keychainManager: keychain,
                keyManager: keyManager,
                attestationProvider: AttestationProvider(),
                enrollmentManager: enrollmentManager,
                apiClient: apiClient
            )
        }
    }

    // MARK: - Device token

    /// Returns the locally-cached device token if the device is enrolled, `nil` otherwise.
    ///
    /// No network call or biometric prompt is made. Safe to call at cold start, from any thread,
    /// before the user authenticates. Returns `nil` if the device has never enrolled, has been
    /// reset, or if the Keychain is unavailable (e.g. device is locked at first boot).
    public var cachedDeviceToken: String? {
        return try? keychainManager?.read(key: KeychainKey.deviceToken)
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

    /// Initiates email OTP fallback for the most recently initiated verification session.
    ///
    /// Call this after catching `biometricFailed` or `biometricCancelled`. The session ID is
    /// managed internally — you do not need to pass it. The SDK hashes the email with SHA-256
    /// internally — do not pre-hash it.
    ///
    /// - Parameters:
    ///   - email: The user's plain-text email address. Never stored or logged by the SDK.
    ///   - reason: Why fallback is being requested.
    /// - Returns: A `FallbackResult` containing the `fallbackSessionId` and OTP expiry.
    /// - Throws: `VouchflowError.noActiveSession` if `verify` has not been called yet or the
    ///   session already completed successfully.
    public func requestFallback(
        email: String,
        reason: FallbackReason = .biometricFailed
    ) async throws -> FallbackResult {
        guard let manager = fallbackManager, let verificationManager else {
            throw VouchflowError.notConfigured
        }
        guard let sessionId = verificationManager.pendingFallbackSessionId else {
            throw VouchflowError.noActiveSession
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

    // MARK: - signPayload

    /// Cryptographically binds a Face ID / Touch ID confirmation to specific
    /// payload content. Use for high-assurance authorization — mandate signing,
    /// transaction approval, key release, identity disclosure consent — where
    /// the proof must include *what* was authorized, not just that a user
    /// confirmation occurred.
    ///
    /// The returned `SignedBundle.assertion` is a JWS signed by Vouchflow.
    /// Your backend verifies it against
    /// `https://api.vouchflow.dev/.well-known/jwks.json` with any JWT
    /// library — no platform cryptography on the server side.
    ///
    /// - Parameters:
    ///   - payload: Any `Encodable`. Canonicalized via RFC 8785 JCS before signing.
    ///   - context: A short audit string (`'mandate_signing'`, `'transfer'`, etc.).
    ///   - minimumConfidence: Defaults to `.high`. With `.high`, the SDK attempts
    ///     App Attest re-attestation; if unavailable the call may downgrade to
    ///     `.medium` and throw `.minimumConfidenceUnmet`.
    /// - Returns: A `SignedBundle` to ship to your backend.
    /// - Throws: `VouchflowError`
    public func signPayload<T: Encodable>(
        _ payload: T,
        context: String,
        minimumConfidence: Confidence = .high
    ) async throws -> SignedBundle {
        guard let manager = signPayloadManager else {
            throw VouchflowError.notConfigured
        }
        return try await manager.signPayload(
            payload: payload,
            context: context,
            minimumConfidence: minimumConfidence
        )
    }

    // MARK: - Reset

    /// Clears all local enrollment data: Secure Enclave key, device token, and pending token.
    ///
    /// After calling this, the next `verify()` call will re-enroll the device. Use in test
    /// harnesses or when implementing an explicit "unlink device" feature.
    public func reset() {
        verificationManager?.reset()
    }

    // MARK: - Test harness utilities

    /// For developer test harnesses: ensures the device is enrolled. Triggers enrollment if needed.
    /// On return, `cachedDeviceToken` will be non-nil if enrollment succeeded.
    ///
    /// Do not use in production app code.
    public func ensureEnrolledForTesting() async throws {
        guard let manager = verificationManager else {
            throw VouchflowError.notConfigured
        }
        try await manager.ensureEnrolledForTesting()
    }

    /// For developer test harnesses: initiates a verify session on the server without biometric
    /// authentication. The session is stored as the pending fallback session, so a subsequent
    /// `requestFallback` call will work without requiring a cancelled biometric prompt.
    ///
    /// Do not use this in production app code.
    public func initiateSessionForFallbackTesting() async throws {
        guard let manager = verificationManager else {
            throw VouchflowError.notConfigured
        }
        _ = try await manager.initiateSession()
    }
}
