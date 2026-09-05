import XCTest
import Security
@testable import VouchflowSDK

/// End-to-end tests for `PinningDelegate.decision(forServerTrust:)` driven by **real**
/// `SecTrust` objects built from the checked-in fixture certificates.
///
/// These are the tests that actually prove the security fix: each one hands the delegate a
/// genuine certificate chain and asserts the disposition. The three marked "would have been
/// ACCEPTED before v2.5.0" fail against the pre-fix delegate, which returned `.useCredential`
/// the moment any certificate's SPKI matched a pin.
///
/// Every chain is anchored explicitly with `SecTrustSetAnchorCertificatesOnly`, so no test
/// can pass or fail because of what the host device's system trust store happens to contain,
/// and every evaluation runs at a fixed `verifyDate`.
final class PinningDelegateTrustTests: XCTestCase {

    private typealias Fixtures = PinningTestCertificates

    /// Any syntactically valid pin that matches nothing in the fixtures.
    private let unrelatedPin = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

    // MARK: - Helpers

    private func delegate(leafPin: String, intermediatePin: String) -> PinningDelegate {
        PinningDelegate(config: VouchflowConfig(
            apiKey: "vsk_test_pinning",
            environment: .production,
            leafCertificatePin: leafPin,
            intermediateCertificatePin: intermediatePin
        ))
    }

    /// Builds a `SecTrust` for `chain` (leaf first, as a server presents it), trusting only
    /// `anchors`, evaluated at `Fixtures.verifyDate`.
    private func makeTrust(chain: [String], anchors: [String]) throws -> SecTrust {
        let certificates = try chain.map {
            try XCTUnwrap(Fixtures.certificate(fromBase64DER: $0), "fixture DER failed to decode")
        }

        var trust: SecTrust?
        XCTAssertEqual(
            SecTrustCreateWithCertificates(certificates as CFArray, SecPolicyCreateBasicX509(), &trust),
            errSecSuccess
        )
        let serverTrust = try XCTUnwrap(trust)

        // Fixed instant: fixture expiry can never turn these tests flaky, and the "expired"
        // fixture is expired by construction rather than by the calendar.
        XCTAssertEqual(
            SecTrustSetVerifyDate(serverTrust, Fixtures.verifyDate as CFDate),
            errSecSuccess
        )

        let anchorCertificates = try anchors.map {
            try XCTUnwrap(Fixtures.certificate(fromBase64DER: $0), "anchor DER failed to decode")
        }
        XCTAssertEqual(
            SecTrustSetAnchorCertificates(serverTrust, anchorCertificates as CFArray),
            errSecSuccess
        )
        XCTAssertEqual(SecTrustSetAnchorCertificatesOnly(serverTrust, true), errSecSuccess)

        return serverTrust
    }

    private func assertRejectedAtTrustEvaluation(
        _ decision: PinningDecision,
        _ message: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        guard case .reject(.trustEvaluationFailed(let reason)) = decision else {
            return XCTFail("\(message) — expected .reject(.trustEvaluationFailed), got \(decision)",
                           file: file, line: line)
        }
        XCTAssertFalse(reason.isEmpty, "trust failure must carry a diagnosable reason",
                       file: file, line: line)
    }

    // MARK: - A valid, pinned chain is accepted

    func test_validChain_matchingLeafPin_isAccepted() throws {
        let trust = try makeTrust(chain: [Fixtures.validLeafDER, Fixtures.caDER],
                                  anchors: [Fixtures.caDER])
        let decision = delegate(leafPin: Fixtures.validLeafSPKI, intermediatePin: unrelatedPin)
            .decision(forServerTrust: trust)
        XCTAssertEqual(decision, .accept)
    }

    /// Pinning at the intermediate is the change Speakeasy wants (it survives leaf rotation).
    /// It must keep working — for the *correct* host.
    func test_validChain_matchingIntermediatePin_isAccepted() throws {
        let trust = try makeTrust(chain: [Fixtures.validLeafDER, Fixtures.caDER],
                                  anchors: [Fixtures.caDER])
        let decision = delegate(leafPin: unrelatedPin, intermediatePin: Fixtures.caSPKI)
            .decision(forServerTrust: trust)
        XCTAssertEqual(decision, .accept)
    }

    // MARK: - Valid chain, no pin match, still rejected (no regression)

    func test_validChain_matchingNoPin_isRejectedAsPinMismatch() throws {
        let trust = try makeTrust(chain: [Fixtures.validLeafDER, Fixtures.caDER],
                                  anchors: [Fixtures.caDER])
        let decision = delegate(leafPin: unrelatedPin, intermediatePin: unrelatedPin)
            .decision(forServerTrust: trust)

        guard case .reject(.pinMismatch(let served)) = decision else {
            return XCTFail("expected .reject(.pinMismatch), got \(decision)")
        }
        // Self-diagnosing failure reporting: the developer gets what was actually served.
        XCTAssertTrue(served.contains(Fixtures.validLeafSPKI),
                      "served chain should report the leaf SPKI; got \(served)")
        XCTAssertTrue(served.contains(Fixtures.caSPKI),
                      "served chain should report the CA SPKI; got \(served)")
    }

    // MARK: - Hostname mismatch (would have been ACCEPTED before v2.5.0)

    /// The exact attack the intermediate-pin migration would otherwise have opened: an
    /// attacker obtains a legitimate certificate for a domain they control from the CA the
    /// SDK pins. Its chain contains the pinned intermediate, so the pin matches — the only
    /// thing that rejects it is hostname-bound trust evaluation.
    func test_attackerCertificateFromThePinnedCA_isRejected() throws {
        let trust = try makeTrust(chain: [Fixtures.attackerLeafDER, Fixtures.caDER],
                                  anchors: [Fixtures.caDER])
        let decision = delegate(leafPin: unrelatedPin, intermediatePin: Fixtures.caSPKI)
            .decision(forServerTrust: trust)
        assertRejectedAtTrustEvaluation(
            decision,
            "a certificate for attacker.example.com must not authenticate api.vouchflow.dev"
        )
    }

    /// Same hostname mismatch, reached through the leaf pin instead, so the rejection cannot
    /// be attributed to which pin happened to match.
    func test_hostnameMismatch_isRejected_evenWhenTheLeafItselfIsPinned() throws {
        let trust = try makeTrust(chain: [Fixtures.attackerLeafDER, Fixtures.caDER],
                                  anchors: [Fixtures.caDER])
        let decision = delegate(leafPin: Fixtures.attackerLeafSPKI, intermediatePin: unrelatedPin)
            .decision(forServerTrust: trust)
        assertRejectedAtTrustEvaluation(decision, "hostname must be validated regardless of pin match")
    }

    // MARK: - Expired chain (would have been ACCEPTED before v2.5.0)

    func test_expiredCertificate_isRejected_evenThoughItsPinMatches() throws {
        let trust = try makeTrust(chain: [Fixtures.expiredLeafDER, Fixtures.caDER],
                                  anchors: [Fixtures.caDER])
        let decision = delegate(leafPin: Fixtures.expiredLeafSPKI, intermediatePin: Fixtures.caSPKI)
            .decision(forServerTrust: trust)
        assertRejectedAtTrustEvaluation(decision, "an expired certificate must not be accepted")
    }

    // MARK: - Untrusted root (would have been ACCEPTED before v2.5.0)

    func test_untrustedRoot_isRejected_evenThoughItsPinMatches() throws {
        // Right hostname, in date, pin matches exactly — and it chains to nothing trusted.
        let trust = try makeTrust(chain: [Fixtures.selfSignedLeafDER], anchors: [])
        let decision = delegate(leafPin: Fixtures.selfSignedLeafSPKI, intermediatePin: unrelatedPin)
            .decision(forServerTrust: trust)
        assertRejectedAtTrustEvaluation(decision, "a chain reaching no trusted root must be rejected")
    }

    // MARK: - Placeholder pins never skip trust evaluation

    func test_placeholderPins_doNotSkipTrustEvaluation() throws {
        let trust = try makeTrust(chain: [Fixtures.selfSignedLeafDER], anchors: [])
        let decision = delegate(leafPin: "TODO-leaf-pin", intermediatePin: "TODO-intermediate-pin")
            .decision(forServerTrust: trust)

        #if DEBUG
        assertRejectedAtTrustEvaluation(
            decision,
            "debug builds skip pin comparison, never chain validation"
        )
        #else
        XCTAssertEqual(decision, .reject(.placeholderPinsInReleaseBuild))
        #endif
    }

    func test_placeholderPins_onAValidChain_skipOnlyPinComparison() throws {
        let trust = try makeTrust(chain: [Fixtures.validLeafDER, Fixtures.caDER],
                                  anchors: [Fixtures.caDER])
        let decision = delegate(leafPin: "TODO-leaf-pin", intermediatePin: "TODO-intermediate-pin")
            .decision(forServerTrust: trust)

        #if DEBUG
        XCTAssertEqual(decision, .acceptPlaceholderPinsInDebugBuild)
        #else
        XCTAssertEqual(decision, .reject(.placeholderPinsInReleaseBuild))
        #endif
    }
}
