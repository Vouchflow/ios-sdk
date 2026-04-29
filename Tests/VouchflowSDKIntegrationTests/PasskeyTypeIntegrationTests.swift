import LocalAuthentication
import XCTest
@testable import VouchflowSDK

/// Integration tests verifying enroll + verify behavior for each device passkey configuration
/// against the sandbox environment.
///
/// ## Simulator (CI)
///
/// All four tests run fully automated on a fresh iOS Simulator (no pre-configuration needed):
///
/// - **Biometric** and **passcode** tests enroll Face ID via `XCUIDevice.shared.biometricEnrollment`,
///   launch `verify()` concurrently, then inject a biometric match via
///   `XCUIDevice.shared.performBiometricMatch()`. The SDK uses `.deviceOwnerAuthentication`
///   internally, so Face ID simulation exercises the same SE signing path as a passcode would.
///
/// - **No-auth** tests run directly. setUp resets biometricEnrollment to `.none` before each
///   test, and the CI Simulator has no passcode, so `verify()` hits `LAError.passcodeNotSet`
///   and throws `VouchflowError.biometricUnavailable` as expected.
///
/// ## Physical device / manual run
///
/// **Biometric (Face ID) enrolled:** Enable Face ID in Settings. While the test waits after
///   calling verify(), trigger Simulator > Features > Face ID > Matching Face.
///
/// **Passcode only (no biometric):** Disable Face ID. Set a passcode in Settings > Face ID &
///   Passcode. While the test waits, enter the passcode in the Simulator prompt.
///
/// **No auth:** Fresh Simulator with no lock screen configured.
final class PasskeyTypeIntegrationTests: XCTestCase {

    override func setUp() async throws {
        try await super.setUp()
        #if targetEnvironment(simulator)
        // Guarantee clean biometric state before every test so no-auth tests see no enrollment.
        XCUIDevice.shared.biometricEnrollment = .none
        #endif
        try StagingTestConfig.configure()
        StagingTestConfig.reset()
    }

    override func tearDown() async throws {
        #if targetEnvironment(simulator)
        XCUIDevice.shared.biometricEnrollment = .none
        #endif
        StagingTestConfig.reset()
        try await super.tearDown()
    }

    // ── Biometric enrolled ────────────────────────────────────────────────────

    /// Face ID (or Touch ID) is enrolled. `verify()` succeeds via biometric authentication.
    ///
    /// **Simulator:** Face ID enrolled and matched automatically via `XCUIDevice`.
    /// **Physical device:** Biometric must be enrolled; trigger Matching Face while test waits.
    func test_biometricEnrolled_enrollAndVerifySucceeds() async throws {
        #if targetEnvironment(simulator)
        try await verifyWithSimulatedBiometric()
        #else
        let ctx = LAContext()
        var error: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            throw XCTSkip("No biometric enrolled — enable Face ID/Touch ID in device Settings")
        }
        let result = try await Vouchflow.shared.verify(context: .login)
        XCTAssertTrue(result.verified, "verified must be true")
        XCTAssertNotNil(Vouchflow.shared.cachedDeviceToken, "device token must be set")
        #endif
    }

    // ── Passcode enrolled (no biometric) ─────────────────────────────────────

    /// Device has a passcode but no biometric. The SDK uses `.deviceOwnerAuthentication`
    /// so iOS presents the passcode UI automatically when biometrics are unavailable.
    ///
    /// **Simulator:** The SDK policy `.deviceOwnerAuthentication` accepts biometric or passcode.
    ///   Face ID simulation satisfies it and exercises the same SE signing path as a passcode.
    /// **Physical device:** Biometric must NOT be enrolled; set a passcode in Settings.
    ///   While the test waits, enter the passcode in the prompt.
    func test_passcodeEnrolled_enrollAndVerifySucceeds() async throws {
        #if targetEnvironment(simulator)
        // The SDK uses .deviceOwnerAuthentication (biometric OR passcode). Satisfying it via
        // biometric simulation on Simulator exercises the same Keystore signing path.
        try await verifyWithSimulatedBiometric()
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
    func test_noAuth_verifyThrowsBiometricUnavailable_enrollmentStillSucceeds() async throws {
        #if targetEnvironment(simulator)
        // setUp sets biometricEnrollment = .none. CI Simulator has no passcode.
        // iOS 18 Simulator may report canEvaluatePolicy as true despite no real credential,
        // so we skip the policy guard on Simulator and drive the test directly.
        #else
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
    func test_noAuth_enrollmentSucceeds_verifyThrows() async throws {
        #if targetEnvironment(simulator)
        // No biometric (setUp resets to .none) and no passcode on CI Simulator.
        #else
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

    // ── Simulator helper ─────────────────────────────────────────────────────

    /// Enrolls Face ID via `XCUIDevice`, runs `verify()` concurrently, then simulates a
    /// biometric match. Used by both the biometric and passcode tests on Simulator.
    ///
    /// The SDK uses `.deviceOwnerAuthentication` internally, so Face ID simulation satisfies
    /// the same policy check that passcode entry would, and exercises the same SE signing path.
    private func verifyWithSimulatedBiometric() async throws {
        XCUIDevice.shared.biometricEnrollment = .enrolled

        var capturedResult: VouchflowResult?
        var capturedError: Error?
        let done = XCTestExpectation(description: "verify() completes")

        // verify() suspends at the LAContext biometric prompt. Launch concurrently so we can
        // inject the match after the two network calls that precede it
        // (POST /v1/enroll + POST /v1/verify, ~1–2s on sandbox).
        Task {
            do { capturedResult = try await Vouchflow.shared.verify(context: .login) }
            catch { capturedError = error }
            done.fulfill()
        }

        // Poll: call performBiometricMatch every 0.75s for up to 6s. If the prompt appears
        // before our first attempt, subsequent calls are no-ops; if it appears late, a later
        // attempt triggers it. This is more robust than a single fixed-duration sleep.
        for _ in 0..<8 {
            try await Task.sleep(nanoseconds: 750_000_000)
            XCUIDevice.shared.performBiometricMatch()
        }

        await fulfillment(of: [done], timeout: 30)

        XCTAssertNil(capturedError, "verify() threw unexpectedly: \(String(describing: capturedError))")
        XCTAssertTrue(capturedResult?.verified == true, "verified must be true")
        XCTAssertNotNil(Vouchflow.shared.cachedDeviceToken, "device token must be set after enroll + verify")
    }
}
