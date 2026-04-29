import Foundation
@testable import VouchflowSDK

/// Shared configuration for sandbox integration tests.
///
/// Uses the Vouchflow sandbox environment — verifications are isolated from production
/// billing and never enter the live network graph.
enum StagingTestConfig {

    // Sandbox write key — safe to commit; sandbox is an isolated environment.
    static let sandboxWriteKey = "vsk_sandbox_20af25f2668a65ae268625ab2235e765153fe11b"

    /// Configures the SDK to hit the sandbox with cert pinning disabled.
    ///
    /// Pinning is disabled via TODO placeholder pins, which `PinningDelegate` skips in
    /// `#if DEBUG` builds. Integration test targets are always debug.
    static func configure() throws {
        try Vouchflow.configure(VouchflowConfig(
            apiKey: sandboxWriteKey,
            environment: .sandbox,
            // TODO prefix → pinning disabled in debug builds (see PinningDelegate.swift)
            leafCertificatePin: "TODO-sandbox-integration-test",
            intermediateCertificatePin: "TODO-sandbox-integration-test"
        ))
    }

    static func reset() {
        Vouchflow.shared.reset()
    }
}
