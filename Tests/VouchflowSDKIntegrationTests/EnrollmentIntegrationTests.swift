import LocalAuthentication
import XCTest
@testable import VouchflowSDK

/// Integration tests for the enrollment state machine against the sandbox environment.
///
/// These tests call `Vouchflow.shared.verify()` to trigger enrollment, then assert the outcome
/// based on the device/Simulator's lock screen configuration.
///
/// ## Running on iOS Simulator
/// Enrollment does not require biometric interaction — the Secure Enclave key is generated
/// unconditionally. `verify()` is called and the expected `biometricUnavailable` error thrown
/// when no passcode is configured (fresh Simulator) confirms enrollment succeeded before
/// the biometric gate was reached.
///
/// Tests that require cancellation of a biometric prompt (`setUp_cancelsBiometricPrompt`)
/// must be run on a Simulator with Face ID enrolled (Simulator > Features > Face ID > Enrolled)
/// and matching triggered externally (Simulator > Features > Face ID > Matching Face) while
/// the test is waiting.
final class EnrollmentIntegrationTests: XCTestCase {

    override func setUp() async throws {
        try await super.setUp()
        try StagingTestConfig.configure()
        StagingTestConfig.reset()
    }

    override func tearDown() async throws {
        StagingTestConfig.reset()
        try await super.tearDown()
    }

    // ── Fresh enrollment ──────────────────────────────────────────────────────

    /// Clean device (no token, no SE key) → POST /v1/enroll → device token written.
    ///
    /// `ensureEnrolledForTesting()` calls `EnrollmentManager.ensureEnrolled()` → POST /v1/enroll.
    /// On success, the device token is written to Keychain.
    func test_freshDevice_enrollSucceeds_deviceTokenWritten() async throws {
        XCTAssertNil(Vouchflow.shared.cachedDeviceToken, "Pre-condition: no device token before enrollment")

        // ensureEnrolledForTesting() → POST /v1/enroll (no biometric required)
        try await Vouchflow.shared.ensureEnrolledForTesting()

        let token = Vouchflow.shared.cachedDeviceToken
        XCTAssertNotNil(token, "Device token must be written after enrollment")
        XCTAssertTrue(token!.hasPrefix("dvt_"), "Device token must start with 'dvt_'")
    }

    // ── Idempotent enrollment ─────────────────────────────────────────────────

    /// Second call to `ensureEnrolledForTesting()` must skip re-enrollment
    /// and return the same device token (SkipEnrollment state).
    func test_alreadyEnrolled_secondCallSkipsEnrollment_tokenUnchanged() async throws {
        // First enrollment
        try await Vouchflow.shared.ensureEnrolledForTesting()
        let firstToken = Vouchflow.shared.cachedDeviceToken
        XCTAssertNotNil(firstToken)

        // Second call — enrollment skipped, same token
        try await Vouchflow.shared.ensureEnrolledForTesting()
        let secondToken = Vouchflow.shared.cachedDeviceToken

        XCTAssertEqual(
            firstToken, secondToken,
            "SkipEnrollment: device token must be unchanged on second call"
        )
    }

    // ── Re-enrollment after reset ─────────────────────────────────────────────

    /// After `reset()`, the next call produces a new device token (FreshEnrollment).
    func test_afterReset_newTokenIssued() async throws {
        // First enrollment
        try await Vouchflow.shared.ensureEnrolledForTesting()
        let firstToken = Vouchflow.shared.cachedDeviceToken
        XCTAssertNotNil(firstToken)

        // Reset wipes SE key + Keychain tokens → FreshEnrollment on next call
        StagingTestConfig.reset()
        XCTAssertNil(Vouchflow.shared.cachedDeviceToken, "Token must be nil after reset")

        // Re-configure after reset (reset clears internal managers)
        try StagingTestConfig.configure()
        try await Vouchflow.shared.ensureEnrolledForTesting()
        let secondToken = Vouchflow.shared.cachedDeviceToken

        XCTAssertNotNil(secondToken, "Re-enrollment must produce a new device token")
        XCTAssertNotEqual(firstToken, secondToken, "Token must differ after reset + re-enroll")
    }

    // ── Reinstall (token present, SE key missing) ─────────────────────────────

    /// Simulates app reinstall: Keychain device token survives (kSecAttrAccessibleAfterFirstUnlock),
    /// but the SE key handle is gone. SDK re-enrolls using the existing token (REINSTALL state).
    func test_reinstall_existingToken_keyDeleted_reEnrollsWithSameToken() async throws {
        // Full enrollment
        try await Vouchflow.shared.ensureEnrolledForTesting()
        let originalToken = Vouchflow.shared.cachedDeviceToken
        XCTAssertNotNil(originalToken)

        // Simulate reinstall: delete SE key handle from Keychain, leave device token intact
        try deleteSecureEnclaveKey()

        // Re-configure to pick up the missing key (new VerificationManager reads Keychain)
        try StagingTestConfig.configure()

        // Next call: REINSTALL state → re-enroll with existing token
        try await Vouchflow.shared.ensureEnrolledForTesting()
        let tokenAfterReinstall = Vouchflow.shared.cachedDeviceToken

        XCTAssertNotNil(tokenAfterReinstall)
        XCTAssertEqual(
            originalToken, tokenAfterReinstall,
            "Reinstall must return the same device token (server preserves reputation)"
        )
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Deletes the Secure Enclave key handle from Keychain, leaving the device token intact.
    /// Mirrors what `SecureEnclaveKeyManager.deleteKey(from:)` does internally.
    private func deleteSecureEnclaveKey() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "dev.vouchflow.sdk",
            kSecAttrAccount as String: "vs_se_key_data"   // KeychainKey.seKeyData
        ]
        let status = SecItemDelete(query as CFDictionary)
        // errSecItemNotFound is acceptable — means the key was already gone
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
    }
}
