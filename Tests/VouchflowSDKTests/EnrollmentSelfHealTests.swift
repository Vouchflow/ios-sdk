import XCTest
@testable import VouchflowSDK

/// Unit tests for the self-heal trigger condition (`EnrollmentManager.shouldSelfHeal`).
///
/// Background: devices that enrolled before the server-side App Attest fix
/// (vouchflow-server#8) are stored `attestation_verified=false`. Their iOS
/// keychain survives app reinstall, so `ensureEnrolled()` returns
/// `.skipEnrollment` forever and they never recover. `shouldSelfHeal` decides
/// when to force a one-time re-enroll. This is the regression-critical logic;
/// the re-enroll plumbing itself is covered by the enrollment integration tests.
final class EnrollmentSelfHealTests: XCTestCase {

    // Heal: App Attest available and the device was never verified.

    func test_heals_whenSupported_andFlagFalse() {
        XCTAssertTrue(EnrollmentManager.shouldSelfHeal(
            appAttestSupported: true, storedAttestationVerified: "false"))
    }

    func test_heals_whenSupported_andFlagAbsent() {
        // Pre-feature enrollments have no flag at all — must still heal.
        XCTAssertTrue(EnrollmentManager.shouldSelfHeal(
            appAttestSupported: true, storedAttestationVerified: nil))
    }

    // No-op: already verified — must not re-enroll an attested device.

    func test_noHeal_whenAlreadyVerified() {
        XCTAssertFalse(EnrollmentManager.shouldSelfHeal(
            appAttestSupported: true, storedAttestationVerified: "true"))
    }

    // No-op: App Attest unavailable (Simulator / unsupported hardware) — never
    // loop on a device that legitimately cannot attest, regardless of the flag.

    func test_noHeal_whenUnsupported_flagFalse() {
        XCTAssertFalse(EnrollmentManager.shouldSelfHeal(
            appAttestSupported: false, storedAttestationVerified: "false"))
    }

    func test_noHeal_whenUnsupported_flagAbsent() {
        XCTAssertFalse(EnrollmentManager.shouldSelfHeal(
            appAttestSupported: false, storedAttestationVerified: nil))
    }

    // Defensive: only the exact string "true" counts as verified, so a garbled
    // value fails safe toward re-enrolling rather than staying stuck low.

    func test_heals_whenSupported_andFlagUnexpectedValue() {
        XCTAssertTrue(EnrollmentManager.shouldSelfHeal(
            appAttestSupported: true, storedAttestationVerified: "TRUE"))
    }
}
