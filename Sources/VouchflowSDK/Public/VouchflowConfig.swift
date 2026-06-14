import Foundation

/// The environment the SDK operates in.
public enum VouchflowEnvironment {
    case production
    case sandbox

    var baseURL: URL {
        switch self {
        case .production:
            return URL(string: "https://api.vouchflow.dev")!
        case .sandbox:
            return URL(string: "https://api.vouchflow.dev")!
        }
    }
}

/// Configuration passed to `Vouchflow.configure(_:)` at app startup.
///
/// ```swift
/// try Vouchflow.configure(VouchflowConfig(
///     apiKey: "vsk_live_...",
///     environment: .production
/// ))
/// ```
public struct VouchflowConfig {
    /// Write-scoped API key. Safe to store in your build config; never use the read-scoped key here.
    public let apiKey: String

    /// Defaults to `.production`. Use `.sandbox` during development — verifications do not
    /// count toward billing and do not enter the network graph.
    public let environment: VouchflowEnvironment

    /// Keychain access group for apps that share Keychain data with extensions or App Clips.
    /// Leave `nil` for standard single-app usage.
    public let keychainAccessGroup: String?

    /// When `true` (default), the device token is persisted in the OS Keychain, so it
    /// survives app reinstall. When `false`, the SDK uses only process-lifetime in-memory
    /// storage — the token does not survive app relaunch, and each launch re-enrolls.
    /// Set `false` for environments that restrict or forbid Keychain use. Note: even when
    /// `true`, the SDK silently falls back to in-memory storage if the Keychain turns out to
    /// be unavailable on the device or profile.
    public let keychainStorage: Bool

    /// Raw base64-encoded SHA-256 of the **server leaf certificate's** SubjectPublicKeyInfo.
    /// No prefix (no `sha256/`, no `pin-sha256=`). To compute against the live endpoint:
    ///
    /// ```bash
    /// openssl s_client -connect api.vouchflow.dev:443 \
    ///     -servername api.vouchflow.dev -showcerts < /dev/null 2>/dev/null \
    ///   | awk '/BEGIN CERT/{c++} c==1,/END CERT/' \
    ///   | openssl x509 -pubkey -noout \
    ///   | openssl pkey -pubin -outform DER \
    ///   | openssl dgst -sha256 -binary | base64
    /// ```
    ///
    /// Placeholder values (starting with `TODO`) disable pinning in debug builds and reject
    /// all requests in release builds.
    public let leafCertificatePin: String

    /// Raw base64-encoded SHA-256 of the **intermediate CA's** SubjectPublicKeyInfo (currently
    /// Let's Encrypt **YE1**). Same format as `leafCertificatePin` — no prefix. Pinning at
    /// the intermediate lets the leaf rotate every 60 days (Fly.io's Let's Encrypt cadence)
    /// without forcing an SDK release.
    ///
    /// Note: do NOT use ISRG Root X1 here. Fly.io's TLS handshake doesn't include the root,
    /// so a root-level pin will never match anything in the served chain.
    ///
    /// Same openssl one-liner as `leafCertificatePin`, but use `c==2` for the second cert.
    public let intermediateCertificatePin: String

    public init(
        apiKey: String,
        environment: VouchflowEnvironment = .production,
        keychainAccessGroup: String? = nil,
        // Live Let's Encrypt YE1 SPKI pins. Refreshed 2026-06-14 against the production chain.
        // When Let's Encrypt rotates intermediates again, refresh both values here using the
        // openssl one-liner documented on `leafCertificatePin`.
        leafCertificatePin: String = "NQ7reZqY0tQjef9LBQwbs0gHjrdrroWrd+scM74zQrU=",
        intermediateCertificatePin: String = "brzvtCELCIZUo4sD/qPX0ccRtPsd3DY6RfmxpOU9oB4=",
        keychainStorage: Bool = true
    ) {
        // Most common pinning misconfig we've seen: integrators read OkHttp/AlamoFire docs,
        // see the `sha256/<value>` format, and prepend `sha256/` here. The SDK works in raw
        // base64 — passing a prefixed value would never match the SDK's own SPKI computation.
        // Fail at configure() with a message naming the fix, before the first network call.
        precondition(
            !leafCertificatePin.hasPrefix("sha256/"),
            "leafCertificatePin must be raw base64 SPKI SHA-256, NOT the OkHttp \"sha256/<hash>\" form. " +
                "The SDK compares raw values. Got: \(leafCertificatePin)"
        )
        precondition(
            !intermediateCertificatePin.hasPrefix("sha256/"),
            "intermediateCertificatePin must be raw base64 SPKI SHA-256, NOT the OkHttp \"sha256/<hash>\" form. " +
                "Got: \(intermediateCertificatePin)"
        )
        self.apiKey = apiKey
        self.environment = environment
        self.keychainAccessGroup = keychainAccessGroup
        self.leafCertificatePin = leafCertificatePin
        self.intermediateCertificatePin = intermediateCertificatePin
        self.keychainStorage = keychainStorage
    }

    var hasTodoPlaceholderPins: Bool {
        leafCertificatePin.hasPrefix("TODO") || intermediateCertificatePin.hasPrefix("TODO")
    }
}
