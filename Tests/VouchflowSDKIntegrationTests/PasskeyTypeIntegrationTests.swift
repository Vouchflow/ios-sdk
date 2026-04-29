import LocalAuthentication
import XCTest
@testable import VouchflowSDK

/// Integration tests verifying enroll + verify behavior for each device passkey configuration
/// against the sandbox environment.
///
/// ## Passkey configurations and how to set up each on iOS Simulator
///
/// **Biometric (Face ID) enrolled:**
///   Simulator > Features > Face ID > Enrolled: ✓
///   While the test is waiting after calling verify(), trigger acceptance via:
///     Simulator > Features > Face ID > Matching Face
///
/// **Passcode enrolled (no Face ID):**
///   Simulator > Features > Face ID > Enrolled: ✗  (leave un-enrolled)
///   Device Settings > Face ID & Passcode > Turn Passcode On → set to e.g. "123456"
///   With `.deviceOwnerAuthentication`, iOS shows the passcode UI when Face ID is absent.
///   While the test is waiting, type the passcode in the Simulator.
///
/// **No auth (fresh Simulator):**
///   No lock screen configured. `LAContext.canEvaluatePolicy` returns false.
///   Tests in this file that test the no-auth path run as regular XCTest and need no external input.
///
/// ## Pattern lock
///   iOS does not have a pattern lock — this configuration is Android-only.
///
/// ## Tests requiring external biometric trigger
///   `test_biometricEnrolled_enrollAndVerifySucceeds` and
///   `test_passcodeEnrolled_enrollAndVerifySucceeds` call `verify()` and then wait up to
///   30 seconds for the result. The developer/CI must interact with the Simulator during
///   this window to accept authentication.
final class PasskeyTypeIntegrationTests: XCTestCase {

    override func setUp() async throws {
        try await super.setUp()
        try StagingTestConfig.configure()
        StagingTestConfig.reset()
    }

    override func tearDown() async throws {
        StagingTestConfig.reset()
        try await super.tearDown()
    }

    // ── Biometric enrolled ────────────────────────────────────────────────────

    /// Face ID (or Touch ID) is enrolled. `verify()` presents the biometric prompt.
    ///
    /// **Before running:** Enable Face ID in Simulator > Features > Face ID > Enrolled.
    /// **While test waits:** Trigger Simulator > Features > Face ID > Matching Face.
    func test_biometricEnrolled_enrollAndVerifySucceeds() async throws {
        let ctx = LAContext()
        var error: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            throw XCTSkip("No biometric enrolled — enable Face ID/Touch ID in Simulator > Features")
        }

        let result = try await Vouchflow.shared.verify(context: .login)

        XCTAssertTrue(result.verified, "verified must be true")
        XCTAssertNotNil(Vouchflow.shared.cachedDeviceToken, "device token must be set after enroll + verify")
    }

    // ── Passcode enrolled (no biometric) ─────────────────────────────────────

    /// Device has a passcode but no biometric enrolled.
    /// iOS `LAContext` with `.deviceOwnerAuthentication` falls back to passcode automatically.
    ///
    /// **Before running:**
    ///   - Un-enroll Face ID (Simulator > Features > Face ID > Enrolled: off)
    ///   - Set a passcode in Simulator Settings > Face ID & Passcode > Turn Passcode On
    /// **While test waits:** Enter the passcode in the Simulator prompt.
    func test_passcodeEnrolled_enrollAndVerifySucceeds() async throws {
        let ctx = LAContext()

        // Skip if biometric is available — biometric test should run instead
        var bioError: NSError?
        if ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &bioError) {
            throw XCTSkip("Biometric is enrolled — run test_biometricEnrolled_enrollAndVerifySucceeds instead")
        }

        // Skip if no passcode either (no-auth device — separate test)
        var credError: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &credError) else {
            throw XCTSkip("No passcode enrolled — set a passcode via Simulator Settings > Face ID & Passcode")
        }

        let result = try await Vouchflow.shared.verify(context: .login)

        XCTAssertTrue(result.verified, "verified must be true")
        XCTAssertNotNil(Vouchflow.shared.cachedDeviceToken, "device token must be set after enroll + verify")
    }

    // ── No auth enrolled ──────────────────────────────────────────────────────

    /// Device has no lock screen configured (no Face ID, no passcode).
    ///
    /// Expected behavior:
    /// - Enrollment (ensureEnrolled) succeeds — SE key generation does not require a passcode.
    /// - `verify()` reaches `LAContext.evaluatePolicy` which fails with `LAError.passcodeNotSet`.
    /// - SDK throws `VouchflowError.biometricUnavailable`.
    /// - Device token IS written (enrollment completed before the biometric gate).
    ///
    /// **Required setup:** Fresh Simulator with no lock screen.
    func test_noAuth_verifyThrowsBiometricUnavailable_enrollmentStillSucceeds() async throws {
        let ctx = LAContext()
        var error: NSError?
        guard !ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            throw XCTSkip("A lock screen is configured — run this test on a Simulator with no passcode/Face ID")
        }

        do {
            _ = try await Vouchflow.shared.verify(context: .login)
            XCTFail("verify() must throw on a device with no authentication configured")
        } catch VouchflowError.biometricUnavailable {
            // Expected — LAError.passcodeNotSet → biometricUnavailable
        } catch {
            XCTFail("Expected biometricUnavailable, got: \(error)")
        }

        // Enrollment ran before the biometric gate — device token should be set
        XCTAssertNotNil(
            Vouchflow.shared.cachedDeviceToken,
            "Enrollment must succeed even when biometric is unavailable: " +
            "SE key generation does not require a passcode on iOS"
        )
    }

    // ── No auth — enrollment explicitly ──────────────────────────────────────

    /// Enrollment via `ensureEnrolledForTesting()` works on a device with no lock screen.
    /// This confirms enrollment and biometric are independent steps.
    func test_noAuth_enrollmentSucceeds_verifyThrows() async throws {
        let ctx = LAContext()
        var error: NSError?
        guard !ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            throw XCTSkip("A lock screen is configured — run on a Simulator with no passcode/Face ID")
        }

        // Enrollment itself has no biometric gate
        try await Vouchflow.shared.ensureEnrolledForTesting()
        XCTAssertNotNil(
            Vouchflow.shared.cachedDeviceToken,
            "Enrollment must succeed without a lock screen"
        )

        // verify() hits the biometric gate and throws
        do {
            _ = try await Vouchflow.shared.verify(context: .login)
            XCTFail("verify() must throw on a no-auth device")
        } catch VouchflowError.biometricUnavailable {
            // Correct
        }
    }
}
