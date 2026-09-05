import XCTest
@testable import VouchflowSDK

/// Exhaustive tests for `PinningPolicy.decide` — the pure decision at the heart of the
/// server-trust challenge.
///
/// The invariant under test is an ordering one: **standard X.509 validation must pass on its
/// own merits before any pin is consulted, and a matching pin can never substitute for it.**
/// Before v2.5.0 the SDK inverted this — a pin match alone produced `.useCredential`, so
/// expiry, revocation, untrusted roots and hostname went unchecked. With the pins moving from
/// the leaf to the Let's Encrypt intermediate (which appears in the chain of every certificate
/// that CA issues) the inversion would have accepted any attacker holding any LE certificate
/// for any domain.
///
/// `PinningDelegateTrustTests` exercises the same rules end-to-end through real `SecTrust`
/// objects; this suite covers the combinations that are awkward to stage with certificates.
final class PinningPolicyTests: XCTestCase {

    private let leafPin = "NQ7reZqY0tQjef9LBQwbs0gHjrdrroWrd+scM74zQrU="
    private let intermediatePin = "brzvtCELCIZUo4sD/qPX0ccRtPsd3DY6RfmxpOU9oB4="
    private let strangerPin = "0000000000000000000000000000000000000000000="

    private func decide(
        trust: TrustEvaluation,
        served: [String],
        pins: [String]? = nil,
        placeholders: Bool = false,
        bypass: Bool = false
    ) -> PinningDecision {
        PinningPolicy.decide(
            trustEvaluation: trust,
            servedSpkiSha256: served,
            configuredPins: pins ?? [leafPin, intermediatePin],
            pinsArePlaceholders: placeholders,
            allowPlaceholderPinBypass: bypass
        )
    }

    // MARK: - Trust evaluation gates everything (the security fix)

    /// The regression this whole change exists to prevent: a pin matches, but the chain is
    /// not valid. Pre-fix behaviour accepted this.
    func test_rejects_whenTrustFails_evenThoughLeafPinMatches() {
        XCTAssertEqual(
            decide(trust: .failed(reason: "expired"), served: [leafPin]),
            .reject(.trustEvaluationFailed(reason: "expired"))
        )
    }

    /// The Let's Encrypt intermediate case specifically: the attacker's own certificate
    /// chains through the pinned CA, so the intermediate pin matches by construction.
    func test_rejects_whenTrustFails_evenThoughIntermediatePinMatches() {
        XCTAssertEqual(
            decide(trust: .failed(reason: "hostname mismatch"), served: [strangerPin, intermediatePin]),
            .reject(.trustEvaluationFailed(reason: "hostname mismatch"))
        )
    }

    func test_rejects_whenTrustFails_andNoPinMatches() {
        XCTAssertEqual(
            decide(trust: .failed(reason: "untrusted root"), served: [strangerPin]),
            .reject(.trustEvaluationFailed(reason: "untrusted root"))
        )
    }

    /// A trust failure is reported as such, never as a pin mismatch — otherwise the next
    /// person debugging an expired certificate goes hunting for a stale pin.
    func test_trustFailureReasonIsCarriedThrough() {
        guard case .reject(.trustEvaluationFailed(let reason)) =
                decide(trust: .failed(reason: "certificate is not standards compliant"), served: [leafPin]) else {
            return XCTFail("expected a trust-evaluation rejection")
        }
        XCTAssertEqual(reason, "certificate is not standards compliant")
    }

    // MARK: - Pinning as an additional constraint (no regression)

    func test_accepts_whenTrustPasses_andLeafPinMatches() {
        XCTAssertEqual(decide(trust: .passed, served: [leafPin, strangerPin]), .accept)
    }

    /// OR semantics across the two pins is what allows zero-downtime leaf rotation.
    func test_accepts_whenTrustPasses_andIntermediatePinMatches() {
        XCTAssertEqual(decide(trust: .passed, served: [strangerPin, intermediatePin]), .accept)
    }

    func test_rejects_whenTrustPasses_butNoPinMatches() {
        XCTAssertEqual(
            decide(trust: .passed, served: [strangerPin]),
            .reject(.pinMismatch(served: [strangerPin]))
        )
    }

    /// The whole served chain is reported, in order, so the developer can diff configured
    /// against served without another round trip.
    func test_pinMismatchReportsEveryServedHash() {
        guard case .reject(.pinMismatch(let served)) =
                decide(trust: .passed, served: [strangerPin, "second", "third"]) else {
            return XCTFail("expected a pin-mismatch rejection")
        }
        XCTAssertEqual(served, [strangerPin, "second", "third"])
    }

    /// A chain whose SPKI hashes could not be computed at all must fail closed.
    func test_rejects_whenTrustPasses_butChainYieldedNoHashes() {
        XCTAssertEqual(decide(trust: .passed, served: []), .reject(.pinMismatch(served: [])))
    }

    /// Fail closed on an unconfigured pin set rather than matching everything.
    func test_rejects_whenNoPinsAreConfigured() {
        XCTAssertEqual(
            decide(trust: .passed, served: [leafPin], pins: []),
            .reject(.pinMismatch(served: [leafPin]))
        )
    }

    /// Blank pins must not match a certificate whose hash could not be computed to a blank
    /// string either — empties are filtered from both the configured set and the comparison.
    func test_rejects_whenBothConfiguredAndServedPinsAreBlank() {
        XCTAssertEqual(
            decide(trust: .passed, served: [""], pins: ["", ""]),
            .reject(.pinMismatch(served: [""]))
        )
    }

    // MARK: - Placeholder pins

    /// Debug builds skip *pin comparison* only. Trust evaluation still gates the connection.
    func test_placeholderPins_inDebug_stillRejectWhenTrustFails() {
        XCTAssertEqual(
            decide(trust: .failed(reason: "untrusted root"), served: [], placeholders: true, bypass: true),
            .reject(.trustEvaluationFailed(reason: "untrusted root"))
        )
    }

    func test_placeholderPins_inDebug_acceptOnceTrustPasses() {
        XCTAssertEqual(
            decide(trust: .passed, served: [strangerPin], placeholders: true, bypass: true),
            .acceptPlaceholderPinsInDebugBuild
        )
    }

    func test_placeholderPins_inRelease_areRejected() {
        XCTAssertEqual(
            decide(trust: .passed, served: [leafPin], placeholders: true, bypass: false),
            .reject(.placeholderPinsInReleaseBuild)
        )
    }

    /// Release + placeholders is a build misconfiguration; report it as one rather than as
    /// a verdict on whatever chain the server happened to present.
    func test_placeholderPins_inRelease_areReportedAsMisconfigurationNotTrustFailure() {
        XCTAssertEqual(
            decide(trust: .failed(reason: "expired"), served: [], placeholders: true, bypass: false),
            .reject(.placeholderPinsInReleaseBuild)
        )
    }
}
