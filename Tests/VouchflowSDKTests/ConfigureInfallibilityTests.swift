import XCTest
@testable import VouchflowSDK

/// Regression coverage for the iOS counterpart of android-sdk issue #1 — `configure()` and
/// first storage access must never crash the host app. Mirrors Android's
/// `ConfigureInfallibilityTest`.
///
/// iOS `configure()` does no synchronous Keychain I/O and `Vouchflow.configure` is `throws`,
/// so it does not carry Android's exact crash. These tests lock that in: `configure()` only
/// throws for a deterministic developer error (an invalid API key), never from storage, and
/// the storage opt-out path is exercised across many iterations.
final class ConfigureInfallibilityTests: XCTestCase {

    private func sandboxConfig(keychainStorage: Bool) -> VouchflowConfig {
        VouchflowConfig(
            apiKey: "vsk_sandbox_configure_infallibility_test",
            environment: .sandbox,
            // TODO prefix disables cert pinning in debug builds.
            leafCertificatePin: "TODO-configure-infallibility-test",
            intermediateCertificatePin: "TODO-configure-infallibility-test",
            keychainStorage: keychainStorage
        )
    }

    /// >=50 repeated configures must never throw — the Keychain-backed default path.
    func test_configure_repeated_neverThrows() {
        for i in 0..<50 {
            XCTAssertNoThrow(
                try Vouchflow.configure(sandboxConfig(keychainStorage: true)),
                "configure() threw on iteration \(i)"
            )
        }
    }

    /// >=50 repeated configures with the Keychain opt-out must never throw.
    func test_configure_keychainStorageDisabled_neverThrows() {
        for i in 0..<50 {
            XCTAssertNoThrow(
                try Vouchflow.configure(sandboxConfig(keychainStorage: false)),
                "configure(keychainStorage: false) threw on iteration \(i)"
            )
        }
    }

    /// `configure()` still surfaces the deterministic developer error — an invalid key.
    func test_configure_invalidKey_throwsInvalidAPIKey() {
        XCTAssertThrowsError(try Vouchflow.configure(VouchflowConfig(apiKey: "not_a_vsk_key"))) { error in
            guard case VouchflowError.invalidAPIKey = error else {
                return XCTFail("expected .invalidAPIKey, got \(error)")
            }
        }
    }

    /// Accessing `cachedDeviceToken` after configure must never throw or crash, on either
    /// storage path.
    func test_cachedDeviceToken_neverThrowsOrCrashes() {
        try? Vouchflow.configure(sandboxConfig(keychainStorage: true))
        _ = Vouchflow.shared.cachedDeviceToken

        try? Vouchflow.configure(sandboxConfig(keychainStorage: false))
        _ = Vouchflow.shared.cachedDeviceToken
    }
}
