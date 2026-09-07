import Foundation
import XCTest
@testable import VouchflowSDK

final class ReviewerFallbackTests: XCTestCase {
    private let code = "0123456789abcdef0123456789abcdef"
    private var client: VouchflowAPIClient!
    private var manager: FallbackManager!
    private var keychain: InMemoryKeychainBackend!

    override func setUp() {
        super.setUp()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [ReviewerFallbackURLProtocol.self]
        client = VouchflowAPIClient(
            config: VouchflowConfig(apiKey: "vsk_live_test", environment: .production),
            sessionConfiguration: configuration
        )
        keychain = InMemoryKeychainBackend()
        keychain.write(key: KeychainKey.deviceToken, value: "dvt_test")
        manager = FallbackManager(keychainManager: keychain, apiClient: client)
    }

    override func tearDown() {
        client.session.invalidateAndCancel()
        ReviewerFallbackURLProtocol.handler = nil
        manager = nil
        client = nil
        keychain = nil
        super.tearDown()
    }

    func testReviewerCompletesThroughSamePinnedSessionWithExactBody() async throws {
        let session = client.session
        var requests: [URLRequest] = []
        ReviewerFallbackURLProtocol.handler = { request in
            requests.append(request)
            XCTAssertEqual(request.httpMethod, "POST")
            XCTAssertEqual(request.url?.path, "/v1/verify/ses_test/fallback")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer vsk_live_test")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Vouchflow-API-Version"), "2026-04-01")
            let body = try Self.body(request)
            if requests.count == 1 {
                XCTAssertEqual(body as? [String: String], [
                    "method": "reviewer_code", "reviewer_code": self.code, "device_token": "dvt_test"
                ])
                return (200, """
                {"verified":true,"confidence":"low","session_id":"ses_test",
                 "session_state":"FALLBACK_COMPLETE","device_token":"dvt_test",
                 "reviewer_provisioned":true,"attestation_verified":false,"fallback_used":true,
                 "fallback_method":"reviewer_code","network_verifications":0}
                """)
            }
            XCTAssertEqual(body["email"] as? String, "reviewer@example.com")
            XCTAssertNil(body["reviewer_code"])
            XCTAssertNil(body["method"])
            return (200, """
            {"fallback_session_id":"fb_test","method":"email_otp",
             "expires_at":"2026-09-07T12:00:00Z","session_state":"FALLBACK_INITIATED"}
            """)
        }

        let result = try await manager.requestFallback(sessionId: "ses_test", reviewerCode: code)
        XCTAssertTrue(result.verified)
        XCTAssertEqual(result.confidence, .low)
        XCTAssertEqual(result.sessionState, "FALLBACK_COMPLETE")
        XCTAssertFalse(result.hasFallbackSignals)
        XCTAssertEqual(requests.count, 1, "Reviewer acceptance must never issue /complete")
        let email = try await manager.requestFallback(
            sessionId: "ses_test", email: "reviewer@example.com", reason: .developerInitiated
        )
        XCTAssertEqual(email.fallbackSessionId, "fb_test")
        XCTAssertEqual(requests.count, 2)
        XCTAssertTrue(client.session === session, "Both fallback variants must reuse the pinned session")
    }

    func testRejectedCodeIsDistinctFromNetworkFailure() async throws {
        ReviewerFallbackURLProtocol.handler = { _ in
            (422, """
            {"error":{"code":"reviewer_code_rejected","message":"Reviewer code could not be accepted"}}
            """)
        }
        do {
            _ = try await manager.requestFallback(sessionId: "ses_test", reviewerCode: code)
            XCTFail("Expected rejection")
        } catch VouchflowError.reviewerCodeRejected {
            // Covers the server's shared invalid/expired/revoked/exhausted/binding error.
        }
    }

    func testNetworkFailureRemainsNetworkFailure() async throws {
        ReviewerFallbackURLProtocol.handler = { _ in throw URLError(.notConnectedToInternet) }
        do {
            _ = try await manager.requestFallback(sessionId: "ses_test", reviewerCode: code)
            XCTFail("Expected network error")
        } catch VouchflowError.networkUnavailable {
            // A failed connection is never presented as a rejected reviewer code.
        }
    }

    func testPinningCancellationRemainsPinningFailure() async throws {
        ReviewerFallbackURLProtocol.handler = { _ in throw URLError(.cancelled) }
        do {
            _ = try await manager.requestFallback(sessionId: "ses_test", reviewerCode: code)
            XCTFail("Expected pinning error")
        } catch VouchflowError.pinningFailure(let hostname, _, _) {
            XCTAssertEqual(hostname, "api.vouchflow.dev")
        }
    }

    func testMalformedRequestRemainsTypedServerError() async throws {
        ReviewerFallbackURLProtocol.handler = { _ in
            (400, """
            {"error":{"code":"invalid_request","message":"Malformed request"}}
            """)
        }
        do {
            _ = try await manager.requestFallback(sessionId: "ses_test", reviewerCode: "malformed")
            XCTFail("Expected server error")
        } catch VouchflowError.serverError(let status, let code, _) {
            XCTAssertEqual(status, 400)
            XCTAssertEqual(code, "invalid_request")
        }
    }

    func testMissingDeviceTokenDoesNotSendRequest() async throws {
        keychain.delete(key: KeychainKey.deviceToken)
        ReviewerFallbackURLProtocol.handler = { _ in
            XCTFail("Must not send a reviewer request without its device token")
            return (500, "{}")
        }
        do {
            _ = try await manager.requestFallback(sessionId: "ses_test", reviewerCode: code)
            XCTFail("Expected missing enrollment error")
        } catch VouchflowError.enrollmentFailed {
            // Reviewer requests require the SDK-owned device token.
        }
    }

    func testEmailOTPStillMapsSignals() async throws {
        ReviewerFallbackURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/verify/fb_test/complete")
            return (200, """
            {"verified":true,"confidence":"low","session_state":"FALLBACK_COMPLETE",
             "fallback_signals":{"ip_consistent":true,"disposable_email_domain":false,
              "device_has_prior_verifications":true,"email_domain_age_days":100,
              "otp_attempts":1,"time_to_complete_seconds":12}}
            """)
        }
        let result = try await manager.submitOTP(sessionId: "fb_test", otp: "123456")
        XCTAssertTrue(result.hasFallbackSignals)
        XCTAssertTrue(result.fallbackSignals.ipConsistent)
        XCTAssertTrue(result.fallbackSignals.deviceHasPriorVerifications)
        XCTAssertEqual(result.fallbackSignals.emailDomainAgeDays, 100)
        XCTAssertEqual(result.fallbackSignals.otpAttempts, 1)
        XCTAssertEqual(result.fallbackSignals.timeToCompleteSeconds, 12)
    }

    func testTerminalSessionClearsOnlyMatchingPendingSession() async throws {
        let config = VouchflowConfig(apiKey: "vsk_live_test", environment: .production)
        let keyManager = SecureEnclaveKeyManager()
        let cache = SessionCache()
        let verification = VerificationManager(
            config: config, keychainManager: keychain, keyManager: keyManager,
            challengeProcessor: ChallengeProcessor(), sessionCache: cache,
            enrollmentManager: EnrollmentManager(
                config: config, keychainManager: keychain, keyManager: keyManager,
                attestationProvider: AttestationProvider(), apiClient: client
            ),
            apiClient: client
        )
        ReviewerFallbackURLProtocol.handler = { request in
            XCTAssertEqual(request.url?.path, "/v1/verify")
            return (200, """
            {"session_id":"ses_current","challenge":"challenge",
             "expires_at":"2026-09-07T12:00:00Z","session_state":"INITIATED"}
            """)
        }
        _ = try await verification.initiateSession()
        verification.completeFallbackSession("ses_old")
        XCTAssertEqual(verification.pendingFallbackSessionId, "ses_current")
        verification.completeFallbackSession("ses_current")
        XCTAssertNil(verification.pendingFallbackSessionId)
    }

    private static func body(_ request: URLRequest) throws -> [String: Any] {
        var data = request.httpBody ?? Data()
        if let stream = request.httpBodyStream {
            stream.open()
            defer { stream.close() }
            var buffer = [UInt8](repeating: 0, count: 1024)
            while stream.hasBytesAvailable {
                let count = stream.read(&buffer, maxLength: buffer.count)
                guard count > 0 else { break }
                data.append(contentsOf: buffer.prefix(count))
            }
        }
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }
}

private final class ReviewerFallbackURLProtocol: URLProtocol {
    static var handler: ((URLRequest) throws -> (Int, String))?

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        do {
            let handler = try XCTUnwrap(Self.handler)
            let (status, body) = try handler(request)
            let response = try XCTUnwrap(HTTPURLResponse(
                url: try XCTUnwrap(request.url), statusCode: status, httpVersion: nil, headerFields: nil
            ))
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: Data(body.utf8))
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}
