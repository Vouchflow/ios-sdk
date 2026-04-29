import LocalAuthentication
import XCTest
@testable import VouchflowSDK

/// Integration tests verifying enroll + verify behavior for each device passkey configuration
/// against the sandbox environment.
///
/// ## Simulator (CI — two-pass run in ios.yml)
///
/// **Pass 1 (no biometric):**
/// - Enrollment tests and no-auth tests run fully.
/// - Biometric test skips via `canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)`.
/// - Passcode test skips via `#if targetEnvironment(simulator)` guard.
///
/// **Pass 2 (Face ID enrolled via `xcrun simctl io booted biometricEnroll`):**
/// - Biometric test runs; CI runs a background `xcrun simctl io biometricMatch` watcher
///   to accept the LAContext prompt while `verify()` is suspended.
/// - No-auth tests are excluded via `-skip-testing` in the CI script (they would fail
///   with biometric active).
/// - Passcode test still skips on Simulator.
///
/// **Note on iOS 18+ Simulator:** `canEvaluatePolicy(.deviceOwnerAuthentication)` returns
/// `true` on iOS 18+ Simulator even with no auth configured. The no-auth tests therefore
/// skip the `.deviceOwnerAuthentication` guard on Simulator and run unconditionally; the
/// CI script excludes them from the biometric pass.
/// `canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)` behaves correctly on all
/// versions (returns false when no biometric is enrolled) and is used as the biometric guard.
///
/// ## Physical device / manual run
///
/// **Biometric (Face ID) enrolled:** Enable Face ID in Settings. While the test waits,
///   trigger Simulator > Features > Face ID > Matching Face (or equivalent on device).
///
/// **Passcode only (no biometric):** Disable Face ID. Set a passcode in Settings > Face ID &
///   Passcode. While the test waits, enter the passcode in the prompt.
///
/// **No auth:** Fresh Simulator with no lock screen configured.
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

    /// Face ID (or Touch ID) is enrolled. `verify()` succeeds via biometric authentication.
    ///
    /// **Simulator CI:** biometric is pre-enrolled via `xcrun simctl io booted biometricEnroll`.
    ///   A background `xcrun simctl io booted biometricMatch` watcher accepts the LAContext prompt.
    /// **Physical device:** Enable Face ID/Touch ID in device Settings before running.
    func test_biometricEnrolled_enrollAndVerifySucceeds() async throws {
        let ctx = LAContext()
        var error: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            throw XCTSkip(
                "No biometric enrolled — on Simulator, pre-enroll via " +
                "`xcrun simctl io booted biometricEnroll`"
            )
        }

        let result = try await Vouchflow.shared.verify(context: .login)
        XCTAssertTrue(result.verified, "verified must be true")
        XCTAssertNotNil(Vouchflow.shared.cachedDeviceToken, "device token must be set")
    }

    // ── Passcode enrolled (no biometric) ─────────────────────────────────────

    /// Device has a passcode but no biometric. The SDK uses `.deviceOwnerAuthentication`
    /// so iOS presents the passcode UI automatically when biometrics are unavailable.
    ///
    /// **Simulator:** Always skips. Passcode-only authentication cannot be reliably
    ///   reproduced on Simulator; the biometric test exercises the same SE signing path
    ///   via `.deviceOwnerAuthentication`.
    /// **Physical device:** Biometric must NOT be enrolled; set a passcode in Settings.
    ///   While the test waits, enter the passcode in the prompt.
    func test_passcodeEnrolled_enrollAndVerifySucceeds() async throws {
        #if targetEnvironment(simulator)
        throw XCTSkip(
            "Passcode-only scenario not reliably reproducible on Simulator — " +
            "covered by the biometric test (same SE signing path via .deviceOwnerAuthentication)"
        )
        #else
        let ctx = LAContext()
        var bioError: NSError?
        if ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &bioError) {
            throw XCTSkip("Biometric is enrolled — run test_biometricEnrolled_enrollAndVerifySucceeds instead")
        }
        var credError: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &credError) else {
            throw XCTSkip("No passcode enrolled — set a passcode via Settings > Face ID & Passcode")
        }
        let result = try await Vouchflow.shared.verify(context: .login)
        XCTAssertTrue(result.verified, "verified must be true")
        XCTAssertNotNil(Vouchflow.shared.cachedDeviceToken, "device token must be set")
        #endif
    }

    // ── No auth enrolled ──────────────────────────────────────────────────────

    /// Device has no lock screen configured (no Face ID, no passcode).
    ///
    /// Expected: enrollment succeeds (SE key generation has no biometric gate on iOS),
    /// then verify() throws `VouchflowError.biometricUnavailable` at the LAContext step.
    ///
    /// **CI:** Runs in pass 1 (before biometric is enrolled). Excluded from pass 2 via
    ///   `-skip-testing` (would fail because verify() succeeds with biometric active).
    func test_noAuth_verifyThrowsBiometricUnavailable_enrollmentStillSucceeds() async throws {
        #if !targetEnvironment(simulator)
        let ctx = LAContext()
        var error: NSError?
        guard !ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            throw XCTSkip("A lock screen is configured — run on a Simulator with no passcode/Face ID")
        }
        #endif

        do {
            _ = try await Vouchflow.shared.verify(context: .login)
            XCTFail("verify() must throw on a device with no authentication configured")
        } catch VouchflowError.biometricUnavailable {
            // Expected — LAError.passcodeNotSet → biometricUnavailable
        } catch {
            XCTFail("Expected biometricUnavailable, got: \(error)")
        }

        // Enrollment ran before the biometric gate — device token must be set.
        XCTAssertNotNil(
            Vouchflow.shared.cachedDeviceToken,
            "Enrollment must succeed even when biometric is unavailable: " +
            "SE key generation does not require a passcode on iOS"
        )
    }

    // ── No auth — enrollment explicitly ──────────────────────────────────────

    /// Enrollment via `ensureEnrolledForTesting()` works on a device with no lock screen.
    /// This confirms enrollment and biometric are independent steps in the SDK.
    ///
    /// **CI:** Runs in pass 1 (before biometric is enrolled). Excluded from pass 2 via
    ///   `-skip-testing`.
    func test_noAuth_enrollmentSucceeds_verifyThrows() async throws {
        #if !targetEnvironment(simulator)
        let ctx = LAContext()
        var error: NSError?
        guard !ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            throw XCTSkip("A lock screen is configured — run on a Simulator with no passcode/Face ID")
        }
        #endif

        try await Vouchflow.shared.ensureEnrolledForTesting()
        XCTAssertNotNil(Vouchflow.shared.cachedDeviceToken, "Enrollment must succeed without a lock screen")

        do {
            _ = try await Vouchflow.shared.verify(context: .login)
            XCTFail("verify() must throw on a no-auth device")
        } catch VouchflowError.biometricUnavailable {
            // Expected
        } catch {
            XCTFail("Expected biometricUnavailable, got: \(error)")
        }
    }
}
