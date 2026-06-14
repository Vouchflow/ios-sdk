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
    /// Provide a retry button. Call `requestFallback(email:reason:)` if the user
    /// opts into email fallback instead.
    ///
    /// - Parameter sessionId: The verification session retained internally for fallback.
    case biometricCancelled(sessionId: String)

    /// The biometric attempt failed (wrong face / finger, lockout, hardware error).
    /// Do not auto-retry more than once. Offer fallback or hard-fail.
    ///
    /// - Parameter sessionId: The verification session retained internally for fallback.
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

    /// The device's persistent token belongs to a different App row on the server.
    ///
    /// Surfaces the server's `device_not_owned` 403. The likeliest cause is an
    /// integrator who created two App rows in the Vouchflow dashboard for what
    /// the server-side model considers a single app with two key types
    /// (sandbox + live). Devices enrolled under App A cannot be verified
    /// through App B's key, even within the same customer.
    ///
    /// Recovery options for the integrator:
    ///
    /// 1. **Consolidate to one App.** In the dashboard, pick the App whose
    ///    keys the production build ships with as the canonical one. Use its
    ///    sandbox key in dev builds, its live key in prod builds.
    /// 2. **Transfer existing devices to the canonical App.** The server
    ///    exposes an admin-keyed endpoint:
    ///
    ///    ```
    ///    POST /v1/customers/:id/apps/:appId/devices/transfer
    ///    Authorization: Bearer $ADMIN_KEY
    ///    { "fromAppId": "...", "deviceTokens": ["...", "..."] }
    ///    ```
    ///
    ///    Bulk-moves Device + Verification rows from `fromAppId` to the
    ///    destination App, within the same customer.
    /// 3. **Wipe and re-enroll.** `Vouchflow.reset()` followed by `verify()`
    ///    mints a fresh device under whichever App the SDK's current API key
    ///    resolves to. Loses the device's history (network signals, confidence
    ///    ceiling, etc.).
    ///
    /// Catch this case explicitly rather than letting it fall through to
    /// `.serverError(403, "device_not_owned", _)` — the recovery is always
    /// integrator-side, never end-user-side, and the SDK can't decide which
    /// option (1/2/3) is right.
    case deviceClaimedElsewhere

    /// Enrollment failed because the device's public key is already registered
    /// under a different customer or app.
    ///
    /// Surfaces the server's `public_key_already_registered` 409. Almost always
    /// one of:
    ///
    /// - The same Secure Enclave key has been used by another tenant (genuine
    ///   cross-tenant claim — talk to support if unexpected).
    /// - The integrator is running the SDK against an App whose dashboard row
    ///   was deleted and re-created; the orphan Device row still holds the
    ///   public key. Resolution: support to release the orphan.
    ///
    /// Notably **not** the same as the old SDK 2.2.x behaviour: as of server
    /// v59 the same-tenant re-token case (e.g. SDK reset() with a surviving
    /// Secure Enclave key) succeeds with the existing device token, so this
    /// error fires only for genuine cross-tenant collisions.
    case publicKeyAlreadyRegistered

    /// The server's TLS certificate did not match the configured pins.
    ///
    /// Either a MITM attack, a Let's Encrypt rotation that left the SDK's pinned values
    /// stale, or an integrator misconfiguration. The associated values let you tell which:
    ///
    /// - `configuredPins` is what you passed in `VouchflowConfig` (raw base64).
    /// - `servedSpkiSha256` is what the server's chain actually presented today, computed
    ///   the same way you computed the pin (no `sha256/` prefix).
    ///
    /// Compare the two. If your configured leaf doesn't appear in the served list, your
    /// pin is stale — re-run the openssl one-liner from `VouchflowConfig.leafCertificatePin`
    /// against the live endpoint to get the current value.
    ///
    /// - Parameters:
    ///   - hostname: Host that failed pinning (e.g. `api.vouchflow.dev`).
    ///   - configuredPins: Raw base64 SPKI SHA-256 pins from `VouchflowConfig`.
    ///   - servedSpkiSha256: Raw base64 SPKI SHA-256 of each certificate in the chain the
    ///     server presented, in the same order. Empty if the chain couldn't be inspected.
    case pinningFailure(hostname: String, configuredPins: [String], servedSpkiSha256: [String])

    // MARK: - signPayload

    /// The payload passed to `signPayload(payload:context:)` cannot be
    /// canonicalized as JSON (contains non-JSON types, NaN/Infinity, etc.).
    case canonicalizationFailed(underlying: Error?)

    /// Server rejected the signed payload — typically because the canonical
    /// bytes the SDK sent at initiate don't match what the device signed.
    /// Should not occur in normal use; indicates SDK or device key bug.
    case payloadSignatureRejected

    // MARK: - Internal (never surfaces to developers)

    /// Carries retry session data from `VouchflowAPIClient` up to `VerificationManager`.
    /// Pattern-matched internally and converted to `sessionExpiredRepeatedly` or a silent retry.
    case __sessionExpiredInternal(retrySessionId: String, retryChallenge: String)
}
