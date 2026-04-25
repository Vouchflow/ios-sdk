# Vouchflow iOS SDK

Device-native identity verification for iOS apps. Vouchflow uses Secure Enclave cryptography and biometrics to verify that a user is operating from a known, trusted device — without passwords or third-party redirects.

## Requirements

- iOS 15+
- Xcode 15+
- Swift 5.9+

## Installation

### Swift Package Manager

In Xcode: **File → Add Package Dependencies**, enter the repository URL, and add `VouchflowSDK` to your app target.

Or add it to `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/vouchflow/ios-sdk", from: "1.0.0"),
],
targets: [
    .target(name: "YourApp", dependencies: ["VouchflowSDK"]),
]
```

## Setup

Call `Vouchflow.configure(_:)` once at app startup, before any other SDK method. The earliest safe point is `application(_:didFinishLaunchingWithOptions:)` or your SwiftUI `App.init`.

```swift
import VouchflowSDK

// UIKit
func application(_ application: UIApplication, didFinishLaunchingWithOptions ...) -> Bool {
    try? Vouchflow.configure(VouchflowConfig(
        apiKey: "vsk_live_..."
    ))
    return true
}

// SwiftUI
@main
struct MyApp: App {
    init() {
        try? Vouchflow.configure(VouchflowConfig(
            apiKey: "vsk_live_..."
        ))
    }
}
```

`apiKey` is your write-scoped API key from the Vouchflow dashboard. It is safe to store in your build config — do not use a read-scoped key here. No `customerId` is required; your customer account is identified server-side from the API key.

## Verification

### Happy path

```swift
do {
    let result = try await Vouchflow.shared.verify(context: .login)
    // result.verified       — Bool
    // result.confidence     — .high / .medium / .low
    // result.deviceToken    — String (pass to your server for reputation queries)
    // result.signals        — VouchflowSignals
    print("Verified with \(result.confidence) confidence")
} catch {
    // Handle errors (see Error Handling below)
}
```

### Verification context

Pass the action the user is performing. This is stored on the verification record and included in webhook payloads.

| Context | Use for |
|---|---|
| `.signup` | New account creation |
| `.login` | Signing in to an existing account |
| `.sensitiveAction` | High-value actions: password change, payment, export |

### Minimum confidence

Require a minimum confidence level. If the device cannot meet it, the SDK throws `minimumConfidenceUnmet` rather than returning a low-confidence result.

```swift
let result = try await Vouchflow.shared.verify(
    context: .sensitiveAction,
    minimumConfidence: .high
)
```

## Server-side verification

After `verify()` succeeds, pass `result.deviceToken` to your server. Your server then calls `GET /v1/device/{token}/reputation` using a **read-scoped key** (`vsk_live_read_...`) to independently confirm:

- `last_verification.completed_at` is within your freshness window (e.g. last 30 seconds)
- `last_verification.confidence` meets your threshold
- `last_verification.context` matches the action being performed
- `risk_score` is acceptable (0–100; higher means more anomalous)

```
Mobile                       Your server                    Vouchflow
  │  verify() succeeds           │                              │
  │  ──── {deviceToken} ────►    │                              │
  │                              │  GET /v1/device/:token/      │
  │                              │  reputation ──────────────►  │
  │                              │  ◄────── {last_verification, │
  │                              │           risk_score, ...} ──│
  │                              │                              │
  │                     check last_verification.completed_at    │
  │                     is within your freshness window (e.g.   │
  │                     30s), confidence meets your threshold,  │
  │                     and risk_score is acceptable            │
```

Never call `GET /v1/device/:token/reputation` from mobile — it requires a read-scoped key that must stay server-side.

## Error handling

```swift
do {
    let result = try await Vouchflow.shared.verify(context: .login)
    // success
} catch VouchflowError.biometricCancelled(let sessionId) {
    // User tapped Cancel on the Face ID / Touch ID prompt.
    // Show a retry button. Optionally offer email fallback:
    let fallback = try await Vouchflow.shared.requestFallback(
        sessionId: sessionId,
        email: currentUserEmail,
        reason: .biometricCancelled
    )
    showOTPInput(expiresAt: fallback.expiresAt)

} catch VouchflowError.biometricFailed(let sessionId) {
    // Biometric failed (wrong face/finger, lockout, hardware error).
    // Offer fallback or hard-fail depending on your policy.
    let fallback = try await Vouchflow.shared.requestFallback(
        sessionId: sessionId,
        email: currentUserEmail,
        reason: .biometricFailed
    )
    showOTPInput(expiresAt: fallback.expiresAt)

} catch VouchflowError.biometricUnavailable {
    // Face ID / Touch ID not enrolled or not available on this device.
    // Hard-fail or gate the feature.

} catch VouchflowError.minimumConfidenceUnmet {
    // Device cannot reach the required confidence level.
    // Do not offer fallback — this is a device posture issue, not a user error.

} catch VouchflowError.networkUnavailable {
    // No network connection. Prompt the user to check connectivity and retry.

} catch VouchflowError.enrollmentFailed {
    // Enrollment failed. The SDK will retry automatically on next launch.
    // You may choose to degrade the experience or hard-fail.

} catch {
    // Unexpected error. Log and surface a generic error state.
}
```

## Email fallback

When biometric verification fails or is unavailable, you can offer email OTP as a fallback. The SDK hashes the email with SHA-256 before transmission for rate-limiting purposes; it is never stored by the server.

### Step 1 — Initiate fallback

Call `requestFallback` with the `sessionId` from the caught error and the user's email address.

```swift
let fallback = try await Vouchflow.shared.requestFallback(
    sessionId: sessionId,    // from VouchflowError.biometricFailed or .biometricCancelled
    email: userEmail,
    reason: .biometricFailed
)
// fallback.fallbackSessionId — pass to submitFallbackOTP
// fallback.expiresAt         — show a countdown timer (5-minute window)
```

### Step 2 — Submit OTP

```swift
let result = try await Vouchflow.shared.submitFallbackOTP(
    sessionId: fallback.fallbackSessionId,
    otp: userEnteredCode
)
// result.verified   — Bool
// result.confidence — always .low for email fallback
```

### Fallback reasons

Pass the most specific reason that applies:

| Reason | When to use |
|---|---|
| `.biometricFailed` | Biometric attempt failed |
| `.biometricCancelled` | User cancelled the biometric prompt |
| `.biometricUnavailable` | Face ID / Touch ID not enrolled or unavailable |
| `.attestationUnavailable` | App Attest not supported on this device |
| `.minimumConfidenceUnmet` | Device cannot meet the required confidence level |
| `.keyInvalidated` | Secure Enclave key was invalidated (e.g. biometric change) |
| `.developerInitiated` | Your app bypassed biometric for its own reasons |

## Result reference

### `VouchflowResult`

Returned by `verify(context:minimumConfidence:)`.

| Property | Type | Description |
|---|---|---|
| `verified` | `Bool` | Whether verification succeeded |
| `confidence` | `Confidence` | `.high`, `.medium`, or `.low` |
| `deviceToken` | `String` | Stable device identifier — pass to your server, which calls `GET /v1/device/{token}/reputation` (read-scoped key) to independently confirm the verification |
| `deviceAgeDays` | `Int` | Days since this device was first enrolled |
| `networkVerifications` | `Int` | Total verifications for this device across the Vouchflow network |
| `firstSeen` | `Date?` | When this device was first enrolled |
| `signals` | `VouchflowSignals` | Device signals (see below) |
| `fallbackUsed` | `Bool` | Always `false` for `VouchflowResult` — fallback returns `FallbackVerificationResult` |
| `context` | `VerificationContext` | The context passed to `verify` |

### `VouchflowSignals`

| Property | Type | Description |
|---|---|---|
| `keychainPersistent` | `Bool` | Device token survived app deletion and reinstall |
| `biometricUsed` | `Bool` | Face ID / Touch ID was used for this verification |
| `crossAppHistory` | `Bool` | Device has verified across more than one Vouchflow-integrated app |
| `anomalyFlags` | `[String]` | Anomaly flags from the network graph — empty for clean devices |
| `attestationVerified` | `Bool` | App Attest was verified at enrollment time |

### `FallbackVerificationResult`

Returned by `submitFallbackOTP(sessionId:otp:)`.

| Property | Type | Description |
|---|---|---|
| `verified` | `Bool` | Whether the OTP was correct |
| `confidence` | `Confidence` | Always `.low` — email OTP proves inbox access, not device presence |
| `sessionState` | `String` | Final session state |
| `fallbackSignals` | `FallbackSignals` | Signals available from the fallback flow |

## Configuration reference

```swift
VouchflowConfig(
    apiKey: "vsk_live_...",          // Required. Write-scoped key from the dashboard.
    environment: .production,        // Optional. .sandbox for development. Default: .production
    keychainAccessGroup: nil,        // Optional. Set for Keychain sharing with extensions or App Clips.
    leafCertificatePin: "...",       // Optional. SHA-256 of the Vouchflow leaf certificate SPKI.
    intermediateCertificatePin: "..." // Optional. SHA-256 of the intermediate CA SPKI.
)
```

No `customerId` is needed in the SDK — your customer account is identified server-side from the API key.

### Environments

| Environment | Base URL | Key prefix |
|---|---|---|
| `.production` | `https://api.vouchflow.dev/v1` | `vsk_live_` |
| `.sandbox` | `https://sandbox.api.vouchflow.dev/v1` | `vsk_sandbox_` |

Sandbox verifications are free, isolated from the network graph, and do not affect billing. The SDK selects the correct host automatically based on the `environment` setting.

### Certificate pinning

The SDK pins the Vouchflow TLS certificate by default. In debug builds, placeholder pin values disable pinning with a runtime warning. **In release builds, placeholder values cause all requests to fail** — replace them with the real pins from the Vouchflow dashboard before shipping.

If a pinning failure is detected at runtime, the SDK throws `VouchflowError.pinningFailure`. This may indicate a MITM attack or a pin rotation — check the dashboard for the current pin values.

## How it works

1. **Enrollment** — On first launch, the SDK generates a key pair in the Secure Enclave and registers the device with the Vouchflow API. App Attest is used to verify the device and app integrity where available. Enrollment is automatic and transparent to the user.

2. **Verification** — When `verify` is called, the SDK retrieves a challenge from the server, presents a Face ID / Touch ID prompt, signs the challenge with the Secure Enclave private key, and submits the signature. The server verifies the signature against the enrolled public key.

3. **Network graph** — Device signals are shared across Vouchflow-integrated apps (with customer consent). A device that has verified across multiple apps builds a richer history, resulting in higher confidence scores.

4. **Fallback** — If biometric is unavailable or fails, email OTP provides a fallback path. The OTP is delivered to the user's email address; only a SHA-256 hash of the address is stored by the server.

## Security notes

- The Secure Enclave private key never leaves the device. Vouchflow only ever sees the public key and challenge signatures.
- Emails are hashed before transmission and are never stored in plaintext by the server.
- The SDK enforces TLS certificate pinning in production builds to prevent interception.
- API keys are SHA-256 hashed before storage — raw keys are never persisted server-side.
