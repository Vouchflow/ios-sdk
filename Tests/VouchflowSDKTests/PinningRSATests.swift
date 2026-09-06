import XCTest
import Security
@testable import VouchflowSDK

/// RSA support and real-root coverage for the SPKI hashing behind `PinningDelegate`.
///
/// The defect this locks down: `spkiSHA256Hash` could only build an SPKI for EC keys, so
/// every RSA certificate in a served chain was silently skipped by the pin loop — an RSA
/// root pin (e.g. ISRG Root X1, Speakeasy's second slot) could never match, leaving iOS
/// with one effective pin and no spare.
///
/// Every hash test performs two independent checks:
/// 1. The SDK's hash equals the value the openssl pipeline produces for the same
///    certificate (`openssl x509 -pubkey -noout | openssl pkey -pubin -outform der |
///    openssl dgst -sha256 -binary | base64`), recorded alongside the fixture when it was
///    checked in.
/// 2. The SDK's hash equals a hash derived in-process by an independent ASN.1 walk of the
///    certificate DER (`IndependentSPKI`), so a wrong fixture constant and an SDK bug
///    cannot cancel out.
final class PinningRSATests: XCTestCase {

    private typealias Fixtures = PinningRealRootCertificates

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

    private func certificate(_ base64DER: String) throws -> SecCertificate {
        let der = try XCTUnwrap(Data(base64Encoded: base64DER, options: [.ignoreUnknownCharacters]))
        return try XCTUnwrap(SecCertificateCreateWithData(nil, der as CFData))
    }

    /// Asserts the SDK hash equals BOTH the openssl-derived fixture constant and the
    /// in-process independent derivation for the same certificate DER.
    private func assertSPKIHash(
        _ base64DER: String,
        equalsOpenSSLPin expected: String,
        _ name: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let der = try XCTUnwrap(Data(base64Encoded: base64DER, options: [.ignoreUnknownCharacters]))
        let cert = try XCTUnwrap(SecCertificateCreateWithData(nil, der as CFData))

        let sdkHash = try XCTUnwrap(
            PinningDelegate(config: VouchflowConfig(
                apiKey: "vsk_test_pinning",
                environment: .production,
                leafCertificatePin: unrelatedPin,
                intermediateCertificatePin: unrelatedPin
            )).spkiSHA256Hash(for: cert),
            "\(name): SDK could not hash this certificate",
            file: file, line: line
        )

        XCTAssertEqual(sdkHash, expected,
                       "\(name): SDK hash must equal the openssl-pipeline value",
                       file: file, line: line)

        let independentlyDerived = try XCTUnwrap(
            IndependentSPKI.spkiPin(ofCertificateDER: der),
            "\(name): independent ASN.1 walk failed",
            file: file, line: line
        )
        XCTAssertEqual(sdkHash, independentlyDerived,
                       "\(name): SDK hash must equal the independent ASN.1 derivation",
                       file: file, line: line)
    }

    /// Builds a `SecTrust` for `chain` (leaf first), trusting only `anchors`, evaluated at
    /// the fixed fixture `verifyDate` — same construction as `PinningDelegateTrustTests`.
    private func makeTrust(chain: [String], anchors: [String]) throws -> SecTrust {
        let certificates = try chain.map { try certificate($0) }
        var trust: SecTrust?
        XCTAssertEqual(
            SecTrustCreateWithCertificates(certificates as CFArray, SecPolicyCreateBasicX509(), &trust),
            errSecSuccess
        )
        let serverTrust = try XCTUnwrap(trust)
        XCTAssertEqual(
            SecTrustSetVerifyDate(serverTrust, PinningTestCertificates.verifyDate as CFDate),
            errSecSuccess
        )
        let anchorCertificates = try anchors.map { try certificate($0) }
        XCTAssertEqual(
            SecTrustSetAnchorCertificates(serverTrust, anchorCertificates as CFArray),
            errSecSuccess
        )
        XCTAssertEqual(SecTrustSetAnchorCertificatesOnly(serverTrust, true), errSecSuccess)
        return serverTrust
    }

    // MARK: - Real roots: SDK hash == openssl pipeline == independent derivation

    /// THE regression test for the defect. ISRG Root X1 is RSA 4096; before the fix the
    /// SDK returned nil for RSA keys and this pin could never match.
    func test_spkiHash_isrgRootX1_rsa4096_matchesOpenSSLPipeline() throws {
        try assertSPKIHash(Fixtures.isrgRootX1DER,
                           equalsOpenSSLPin: "C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=",
                           "ISRG Root X1 (RSA 4096)")
    }

    /// ISRG Root X2 is EC P-384 — the EC path must stay byte-identical on real P-384
    /// bytes, not just the P-256 fixtures the older tests use.
    func test_spkiHash_isrgRootX2_ecP384_matchesOpenSSLPipeline() throws {
        try assertSPKIHash(Fixtures.isrgRootX2DER,
                           equalsOpenSSLPin: "diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI=",
                           "ISRG Root X2 (EC P-384)")
    }

    /// RSA 2048 and 3072 are the other standard sizes the RSA path must cover.
    func test_spkiHash_generatedRSA2048Root_matchesOpenSSLPipeline() throws {
        try assertSPKIHash(Fixtures.rsa2048RootDER,
                           equalsOpenSSLPin: Fixtures.rsa2048RootSPKI,
                           "generated RSA-2048 root")
    }

    func test_spkiHash_generatedRSA3072Root_matchesOpenSSLPipeline() throws {
        try assertSPKIHash(Fixtures.rsa3072RootDER,
                           equalsOpenSSLPin: Fixtures.rsa3072RootSPKI,
                           "generated RSA-3072 root")
    }

    func test_spkiHash_generatedRSA4096Root_matchesOpenSSLPipeline() throws {
        try assertSPKIHash(Fixtures.rsa4096RootDER,
                           equalsOpenSSLPin: Fixtures.rsa4096RootSPKI,
                           "generated RSA-4096 root")
    }

    // MARK: - End-to-end: the pin loop actually matches an RSA certificate

    /// Full decision path over a mixed EC-leaf / RSA-4096-root chain: the RSA root's hash
    /// must reach the pin comparison and match the second configured slot. Before the fix,
    /// the root was skipped and this exact configuration could never be satisfied.
    func test_chainWithRSARoot_matchingRootPin_isAccepted() throws {
        let trust = try makeTrust(chain: [Fixtures.rsaChainLeafDER, Fixtures.rsa4096RootDER],
                                  anchors: [Fixtures.rsa4096RootDER])
        let decision = delegate(leafPin: unrelatedPin,
                                intermediatePin: Fixtures.rsa4096RootSPKI)
            .decision(forServerTrust: trust)
        XCTAssertEqual(decision, .accept)
    }

    /// OR semantics are unchanged: the same chain also accepts on a leaf-pin match, and
    /// neither acceptance may depend on which slot the pin sits in.
    func test_chainWithRSARoot_matchingLeafPin_isAccepted() throws {
        let trust = try makeTrust(chain: [Fixtures.rsaChainLeafDER, Fixtures.rsa4096RootDER],
                                  anchors: [Fixtures.rsa4096RootDER])
        let decision = delegate(leafPin: Fixtures.rsaChainLeafSPKI,
                                intermediatePin: unrelatedPin)
            .decision(forServerTrust: trust)
        XCTAssertEqual(decision, .accept)
    }

    /// The pre-fix failure mode, asserted positively: with no matching pin, the RSA root's
    /// hash must appear in the served hashes of the pin-mismatch rejection. Before the fix
    /// the RSA certificate was `continue`d past, so it never appeared there at all — and a
    /// developer diffing configured vs. served pins could never see what the root served.
    func test_pinMismatch_reportsTheRSACertificatesHash() throws {
        let trust = try makeTrust(chain: [Fixtures.rsaChainLeafDER, Fixtures.rsa4096RootDER],
                                  anchors: [Fixtures.rsa4096RootDER])
        let decision = delegate(leafPin: unrelatedPin, intermediatePin: unrelatedPin)
            .decision(forServerTrust: trust)

        guard case .reject(.pinMismatch(let served)) = decision else {
            return XCTFail("expected .reject(.pinMismatch), got \(decision)")
        }
        XCTAssertTrue(served.contains(Fixtures.rsaChainLeafSPKI),
                      "served hashes should include the EC leaf; got \(served)")
        XCTAssertTrue(served.contains(Fixtures.rsa4096RootSPKI),
                      "served hashes must include the RSA root's SPKI — skipping it is the defect; got \(served)")
    }

    /// A valid chain whose RSA root hash matches but which fails standard validation is
    /// still rejected at trust evaluation — the pin never substitutes for TLS validation,
    /// and the RSA fix does not change that ordering.
    func test_chainWithRSARoot_failingTrustEvaluation_isRejectedBeforePins() throws {
        // No anchors: the chain reaches nothing trusted, so evaluation must fail even
        // though the root's pin is configured in both slots.
        let trust = try makeTrust(chain: [Fixtures.rsaChainLeafDER, Fixtures.rsa4096RootDER],
                                  anchors: [])
        let decision = delegate(leafPin: Fixtures.rsa4096RootSPKI,
                                intermediatePin: Fixtures.rsa4096RootSPKI)
            .decision(forServerTrust: trust)
        guard case .reject(.trustEvaluationFailed(let reason)) = decision else {
            return XCTFail("expected .reject(.trustEvaluationFailed), got \(decision)")
        }
        XCTAssertFalse(reason.isEmpty)
    }
}
