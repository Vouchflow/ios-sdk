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
            return URL(string: "https://sandbox.api.vouchflow.dev")!
        }
    }
}

/// Configuration passed to `Vouchflow.configure(_:)` at app startup.
///
/// ```swift
/// try Vouchflow.configure(VouchflowConfig(
///     apiKey: "vsk_live_...",
///     customerId: "cust_abc123",
///     environment: .production
/// ))
/// ```
public struct VouchflowConfig {
    /// Write-scoped API key. Safe to store in your build config; never use the read-scoped key here.
    public let apiKey: String

    /// Your Vouchflow customer ID (e.g. `cust_abc123`). Included in enroll and verify requests
    /// so the server can scope device tokens to your account.
    public let customerId: String

    /// Defaults to `.production`. Use `.sandbox` during development — verifications do not
    /// count toward billing and do not enter the network graph.
    public let environment: VouchflowEnvironment

    /// Keychain access group for apps that share Keychain data with extensions or App Clips.
    /// Leave `nil` for standard single-app usage.
    public let keychainAccessGroup: String?

    /// SHA-256 hash of the Vouchflow leaf TLS certificate's SubjectPublicKeyInfo (DER, base64-encoded).
    ///
    /// **TODO:** Replace with the real pin once the VPS is configured with Caddy.
    /// In debug builds, placeholder values disable pinning with a runtime warning.
    /// In release builds, placeholder values cause all requests to fail — do not ship without real pins.
    public let leafCertificatePin: String

    /// SHA-256 hash of the Vouchflow intermediate CA's SubjectPublicKeyInfo (DER, base64-encoded).
    ///
    /// **TODO:** Replace with the real pin once the VPS is configured with Caddy.
    public let intermediateCertificatePin: String

    public init(
        apiKey: String,
        customerId: String,
        environment: VouchflowEnvironment = .production,
        keychainAccessGroup: String? = nil,
        leafCertificatePin: String = "TODO-leaf-pin-sha256",
        intermediateCertificatePin: String = "TODO-intermediate-pin-sha256"
    ) {
        self.apiKey = apiKey
        self.customerId = customerId
        self.environment = environment
        self.keychainAccessGroup = keychainAccessGroup
        self.leafCertificatePin = leafCertificatePin
        self.intermediateCertificatePin = intermediateCertificatePin
    }

    var hasTodoPlaceholderPins: Bool {
        leafCertificatePin.hasPrefix("TODO") || intermediateCertificatePin.hasPrefix("TODO")
    }
}
