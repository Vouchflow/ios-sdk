import XCTest
@testable import VouchflowSDK

// Additional model encoding/decoding tests that extend ModelEncodingTests.swift.
// Tests in ModelEncodingTests.swift are NOT duplicated here — read that file first.
// This file covers: CompleteVerification{Request,Response}, VerifyResponse,
// FallbackResponse, FallbackCompleteRequest, and APIErrorResponse retry fields.

private let encoder: JSONEncoder = {
    let e = JSONEncoder()
    e.keyEncodingStrategy = .convertToSnakeCase
    e.dateEncodingStrategy = .iso8601
    return e
}()

private let decoder: JSONDecoder = {
    let d = JSONDecoder()
    d.keyDecodingStrategy = .convertFromSnakeCase
    d.dateDecodingStrategy = .iso8601
    return d
}()

private func encodeToDict<T: Encodable>(_ value: T) throws -> [String: Any] {
    let data = try encoder.encode(value)
    return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
}

// MARK: - CompleteVerificationRequest encoding

final class CompleteVerificationRequestEncodingTests: XCTestCase {

    func test_allFieldsEncodeWithCorrectSnakeCaseKeys() throws {
        let req = CompleteVerificationRequest(
            deviceToken: "dvt_abc123",
            signedChallenge: "base64sig==",
            biometricUsed: true
        )
        let dict = try encodeToDict(req)

        XCTAssertEqual(dict["device_token"] as? String, "dvt_abc123")
        XCTAssertEqual(dict["signed_challenge"] as? String, "base64sig==")
        XCTAssertEqual(dict["biometric_used"] as? Bool, true)
    }

    func test_biometricUsed_false_encodesCorrectly() throws {
        let req = CompleteVerificationRequest(
            deviceToken: "dvt_xyz",
            signedChallenge: "sig==",
            biometricUsed: false
        )
        let dict = try encodeToDict(req)
        XCTAssertEqual(dict["biometric_used"] as? Bool, false)
    }

    func test_noUnexpectedFieldsPresent() throws {
        let req = CompleteVerificationRequest(
            deviceToken: "dvt_abc",
            signedChallenge: "sig==",
            biometricUsed: true
        )
        let dict = try encodeToDict(req)
        let keys = Set(dict.keys)
        XCTAssertEqual(keys, ["device_token", "signed_challenge", "biometric_used"])
    }
}

// MARK: - VerifyResponse decoding

final class VerifyResponseDecodingTests: XCTestCase {

    func test_decodesAllFields() throws {
        let json = """
        {
            "session_id": "sess_abc123",
            "challenge": "base64challenge==",
            "expires_at": "2026-04-26T10:00:00Z",
            "session_state": "AWAITING_CHALLENGE"
        }
        """.data(using: .utf8)!

        let response = try decoder.decode(VerifyResponse.self, from: json)

        XCTAssertEqual(response.sessionId, "sess_abc123")
        XCTAssertEqual(response.challenge, "base64challenge==")
        XCTAssertEqual(response.sessionState, "AWAITING_CHALLENGE")
        // expiresAt is decoded as a Date — verify it round-trips correctly.
        XCTAssertNotNil(response.expiresAt)
    }

    func test_expiresAt_parsesISO8601() throws {
        let json = """
        {
            "session_id": "sess_x",
            "challenge": "ch==",
            "expires_at": "2026-04-26T12:30:00Z",
            "session_state": "AWAITING_CHALLENGE"
        }
        """.data(using: .utf8)!

        let response = try decoder.decode(VerifyResponse.self, from: json)

        let cal = Calendar(identifier: .gregorian)
        var comps = cal.dateComponents(in: TimeZone(secondsFromGMT: 0)!, from: response.expiresAt)
        XCTAssertEqual(comps.year, 2026)
        XCTAssertEqual(comps.month, 4)
        XCTAssertEqual(comps.day, 26)
        XCTAssertEqual(comps.hour, 12)
        XCTAssertEqual(comps.minute, 30)
    }
}

// MARK: - CompleteVerificationResponse decoding

final class CompleteVerificationResponseDecodingTests: XCTestCase {

    private let fullJSON = """
    {
        "verified": true,
        "confidence": "high",
        "session_state": "VERIFIED",
        "device_token": "dvt_abc123",
        "device_age_days": 42,
        "network_verifications": 7,
        "first_seen": "2025-01-15T08:00:00Z",
        "signals": {
            "keychain_persistent": true,
            "biometric_used": true,
            "cross_app_history": false,
            "anomaly_flags": [],
            "attestation_verified": true
        },
        "fallback_used": false,
        "context": "login"
    }
    """

    func test_topLevelFieldsDecode() throws {
        let response = try decoder.decode(
            CompleteVerificationResponse.self,
            from: fullJSON.data(using: .utf8)!
        )
        XCTAssertTrue(response.verified)
        XCTAssertEqual(response.confidence, "high")
        XCTAssertEqual(response.sessionState, "VERIFIED")
        XCTAssertEqual(response.deviceToken, "dvt_abc123")
        XCTAssertEqual(response.deviceAgeDays, 42)
        XCTAssertEqual(response.networkVerifications, 7)
        XCTAssertFalse(response.fallbackUsed)
        XCTAssertEqual(response.context, "login")
    }

    func test_signalsPayloadDecodes() throws {
        let response = try decoder.decode(
            CompleteVerificationResponse.self,
            from: fullJSON.data(using: .utf8)!
        )
        let signals = response.signals
        XCTAssertTrue(signals.keychainPersistent)
        XCTAssertTrue(signals.biometricUsed)
        XCTAssertFalse(signals.crossAppHistory)
        XCTAssertTrue(signals.anomalyFlags.isEmpty)
        XCTAssertTrue(signals.attestationVerified)
    }

    func test_anomalyFlagsWithContent() throws {
        let json = """
        {
            "verified": false,
            "confidence": "low",
            "session_state": "FAILED",
            "device_token": "dvt_x",
            "device_age_days": 1,
            "network_verifications": 0,
            "first_seen": null,
            "signals": {
                "keychain_persistent": false,
                "biometric_used": false,
                "cross_app_history": false,
                "anomaly_flags": ["sim_swap", "rooted_device"],
                "attestation_verified": false
            },
            "fallback_used": true,
            "context": "signup"
        }
        """.data(using: .utf8)!

        let response = try decoder.decode(CompleteVerificationResponse.self, from: json)
        XCTAssertEqual(response.signals.anomalyFlags, ["sim_swap", "rooted_device"])
        XCTAssertNil(response.firstSeen)
        XCTAssertTrue(response.fallbackUsed)
    }

    func test_confidenceNull_decodesAsNil() throws {
        let json = """
        {
            "verified": false,
            "confidence": null,
            "session_state": "FAILED",
            "device_token": "dvt_x",
            "device_age_days": 0,
            "network_verifications": 0,
            "first_seen": null,
            "signals": {
                "keychain_persistent": false,
                "biometric_used": false,
                "cross_app_history": false,
                "anomaly_flags": [],
                "attestation_verified": false
            },
            "fallback_used": false,
            "context": "login"
        }
        """.data(using: .utf8)!

        let response = try decoder.decode(CompleteVerificationResponse.self, from: json)
        XCTAssertNil(response.confidence)
    }
}

// MARK: - FallbackResponse decoding

final class FallbackResponseDecodingTests: XCTestCase {

    func test_decodesAllFields() throws {
        let json = """
        {
            "fallback_session_id": "fb_sess_abc123",
            "method": "email_otp",
            "expires_at": "2026-04-26T10:05:00Z",
            "session_state": "AWAITING_OTP"
        }
        """.data(using: .utf8)!

        let response = try decoder.decode(FallbackResponse.self, from: json)

        XCTAssertEqual(response.fallbackSessionId, "fb_sess_abc123")
        XCTAssertEqual(response.method, "email_otp")
        XCTAssertEqual(response.sessionState, "AWAITING_OTP")
        XCTAssertNotNil(response.expiresAt)
    }

    func test_expiresAt_parsesISO8601() throws {
        let json = """
        {
            "fallback_session_id": "fb_x",
            "method": "email_otp",
            "expires_at": "2026-04-26T09:00:00Z",
            "session_state": "AWAITING_OTP"
        }
        """.data(using: .utf8)!

        let response = try decoder.decode(FallbackResponse.self, from: json)

        let cal = Calendar(identifier: .gregorian)
        let comps = cal.dateComponents(in: TimeZone(secondsFromGMT: 0)!, from: response.expiresAt)
        XCTAssertEqual(comps.hour, 9)
    }
}

// MARK: - FallbackCompleteRequest encoding

final class FallbackCompleteRequestEncodingTests: XCTestCase {

    func test_otpEncodesCorrectly() throws {
        let req = FallbackCompleteRequest(otp: "482901", deviceToken: "dvt_abc")
        let dict = try encodeToDict(req)

        XCTAssertEqual(dict["otp"] as? String, "482901")
        XCTAssertEqual(dict["device_token"] as? String, "dvt_abc")
    }

    func test_nullDeviceToken_isAbsent() throws {
        let req = FallbackCompleteRequest(otp: "123456", deviceToken: nil)
        let dict = try encodeToDict(req)

        XCTAssertNil(dict["device_token"], "device_token must be absent when nil")
        XCTAssertEqual(dict["otp"] as? String, "123456")
    }

    func test_noUnexpectedFieldsPresent_withToken() throws {
        let req = FallbackCompleteRequest(otp: "000000", deviceToken: "dvt_x")
        let dict = try encodeToDict(req)
        XCTAssertEqual(Set(dict.keys), Set(["otp", "device_token"]))
    }

    func test_noUnexpectedFieldsPresent_withoutToken() throws {
        let req = FallbackCompleteRequest(otp: "000000", deviceToken: nil)
        let dict = try encodeToDict(req)
        XCTAssertEqual(Set(dict.keys), Set(["otp"]))
    }
}

// MARK: - APIErrorResponse with retry fields

final class APIErrorResponseDecodingTests: XCTestCase {

    func test_decodesRetrySessionIdAndRetryChallenge() throws {
        let json = """
        {
            "error": {
                "code": "session_expired",
                "message": "The session has expired.",
                "retry_session_id": "sess_retry_xyz",
                "retry_challenge": "challenge_abc=="
            }
        }
        """.data(using: .utf8)!

        let response = try decoder.decode(APIErrorResponse.self, from: json)

        XCTAssertEqual(response.error.code, "session_expired")
        XCTAssertEqual(response.error.message, "The session has expired.")
        XCTAssertEqual(response.error.retrySessionId, "sess_retry_xyz")
        XCTAssertEqual(response.error.retryChallenge, "challenge_abc==")
    }

    func test_retryFieldsAreNilWhenAbsent() throws {
        let json = """
        {
            "error": {
                "code": "verification_impossible",
                "message": "Cannot meet confidence threshold."
            }
        }
        """.data(using: .utf8)!

        let response = try decoder.decode(APIErrorResponse.self, from: json)

        XCTAssertEqual(response.error.code, "verification_impossible")
        XCTAssertNil(response.error.retrySessionId)
        XCTAssertNil(response.error.retryChallenge)
    }

    func test_decodesMessageAsNil_whenAbsent() throws {
        // APIErrorDetail.message is optional — some error codes carry no human-readable message.
        let json = """
        {
            "error": {
                "code": "rate_limited"
            }
        }
        """.data(using: .utf8)!

        let response = try decoder.decode(APIErrorResponse.self, from: json)

        XCTAssertEqual(response.error.code, "rate_limited")
        XCTAssertNil(response.error.message)
    }

    func test_expiresAt_decodesWhenPresent() throws {
        let json = """
        {
            "error": {
                "code": "session_expired",
                "message": "Expired.",
                "retry_session_id": "r",
                "retry_challenge": "c",
                "expires_at": "2026-04-26T11:00:00Z"
            }
        }
        """.data(using: .utf8)!

        let response = try decoder.decode(APIErrorResponse.self, from: json)
        XCTAssertNotNil(response.error.expiresAt)
    }
}
