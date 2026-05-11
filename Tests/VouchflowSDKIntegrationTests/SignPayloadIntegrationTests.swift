import LocalAuthentication
import XCTest
@testable import VouchflowSDK

/// Integration tests for `signPayload` against the sandbox environment.
///
/// These exercise the full ceremony: enroll (if needed) → POST /v1/sign
/// initiate → biometric → SE signature → POST /v1/sign/:id/complete → JWS
/// returned. The JWS verification against JWKS happens server-side; these
/// tests assert the SDK plumbing returns a well-formed bundle.
///
/// ## Simulator caveats
/// - No App Attest → `signPayload(..., minimumConfidence: .high)` will
///   complete server-side but the achieved confidence may be `medium` if
///   the device was enrolled without App Attest at all, or if generateAssertion
///   fails on Simulator. The high-confidence assertion exists only on real
///   devices. CI Simulator tests use `.medium` to avoid that flake.
/// - No biometric → tests calling signPayload must first enroll Face ID via
///   `XCUIDevice.shared.biometricEnrollment = .matchingFace`. The biometric
///   gate is identical to verify() — see PasskeyTypeIntegrationTests.
final class SignPayloadIntegrationTests: XCTestCase {

    override func setUp() async throws {
        try await super.setUp()
        try StagingTestConfig.configure()
        StagingTestConfig.reset()
    }

    override func tearDown() async throws {
        StagingTestConfig.reset()
        try await super.tearDown()
    }

    /// signPayload returns a SignedBundle with all fields populated.
    /// CI's `xcrun simctl io booted biometricMatch` background watcher
    /// accepts the LAContext prompt that fires during the SE signature —
    /// same pattern as `PasskeyTypeIntegrationTests.biometricEnrolled_*`.
    func test_signPayload_returnsWellFormedBundle() async throws {
        // Skip when no biometric is enrolled — the LAContext prompt would
        // hang otherwise (the prompt UI doesn't auto-resolve on a fresh
        // Simulator). CI pass 2 enrolls Face ID via simctl before this
        // test runs; pass 1 lets it skip cleanly.
        let ctx = LAContext()
        var canEvalErr: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &canEvalErr) else {
            throw XCTSkip(
                "No biometric enrolled — on Simulator, pre-enroll via " +
                "`xcrun simctl io booted biometricEnroll`"
            )
        }

        // Pre-enroll without biometric so the sign call's biometric prompt
        // is the only auth step.
        try await Vouchflow.shared.ensureEnrolledForTesting()

        struct Mandate: Encodable {
            let v: Int
            let id: String
            let scope: String
        }
        let mandate = Mandate(v: 1, id: "mand_test", scope: "send")

        let bundle = try await Vouchflow.shared.signPayload(
            mandate,
            context: "mandate_signing",
            minimumConfidence: .medium  // see Simulator caveat above
        )

        XCTAssertEqual(bundle.context, "mandate_signing")
        XCTAssertEqual(bundle.platform, "ios")
        XCTAssertTrue(bundle.signingDeviceId.hasPrefix("sdv_"))
        XCTAssertTrue(bundle.deviceToken.hasPrefix("dvt_"))
        XCTAssertEqual(bundle.assertion.split(separator: ".").count, 3, "Assertion must be a JWS")
        // Confidence must be at least medium per the request.
        XCTAssertTrue([Confidence.medium, .high].contains(bundle.confidence))

        // Canonicalized payload must round-trip — same keys in sorted order.
        // The expected canonical is what JCS produces from the input.
        let expected = #"{"id":"mand_test","scope":"send","v":1}"#
        XCTAssertEqual(bundle.payload, expected)
    }

    /// Calling signPayload with a non-Encodable shape is impossible at
    /// compile time, so we exercise the canonicalization-failure path with
    /// a value that NaN-corrupts the JSON encoding.
    func test_signPayload_rejectsNonFiniteNumber() async throws {
        try await Vouchflow.shared.ensureEnrolledForTesting()

        struct Bad: Encodable {
            let amount: Double  // Will be set to .infinity
            func encode(to encoder: Encoder) throws {
                var container = encoder.container(keyedBy: CodingKeys.self)
                // JSONEncoder rejects .infinity unless nonConformingFloatEncodingStrategy is set.
                try container.encode(amount, forKey: .amount)
            }
            enum CodingKeys: String, CodingKey { case amount }
        }

        do {
            _ = try await Vouchflow.shared.signPayload(
                Bad(amount: .infinity),
                context: "x",
                minimumConfidence: .medium
            )
            XCTFail("Should have thrown canonicalizationFailed")
        } catch VouchflowError.canonicalizationFailed {
            // expected
        } catch {
            XCTFail("Expected canonicalizationFailed, got \(error)")
        }
    }
}
