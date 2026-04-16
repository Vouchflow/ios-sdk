import XCTest
@testable import VouchflowSDK

// Tests that each request/response model serialises to the exact JSON the server expects.
// The encoder/decoder mirrors what VouchflowAPIClient uses in production.

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

// MARK: - EnrollRequest

final class EnrollRequestEncodingTests: XCTestCase {

    func test_topLevelFields_present() throws {
        let req = EnrollRequest(
            idempotencyKey: "ik_abc",
            platform: "ios",
            reason: "fresh_enrollment",
            attestation: nil,
            publicKey: "base64key==",
            deviceToken: nil
        )
        let dict = try encodeToDict(req)

        XCTAssertEqual(dict["idempotency_key"] as? String, "ik_abc")
        XCTAssertNil(dict["customer_id"])  // no longer sent — server derives from API key
        XCTAssertEqual(dict["platform"] as? String, "ios")
        XCTAssertEqual(dict["reason"] as? String, "fresh_enrollment")
        XCTAssertEqual(dict["public_key"] as? String, "base64key==")
        // nil device_token should be absent (not encoded as null)
        XCTAssertNil(dict["device_token"])
    }

    func test_attestation_hasNoplatformField() throws {
        let req = EnrollRequest(
            idempotencyKey: "ik_abc",
            platform: "ios",
            reason: "fresh_enrollment",
            attestation: EnrollRequest.AttestationPayload(token: "tok", keyId: "kid_1"),
            publicKey: "base64key==",
            deviceToken: nil
        )
        let dict = try encodeToDict(req)
        let attestation = try XCTUnwrap(dict["attestation"] as? [String: Any])

        XCTAssertEqual(attestation["token"] as? String, "tok")
        XCTAssertEqual(attestation["key_id"] as? String, "kid_1")
        // platform must NOT appear inside attestation (server rejects unknown fields)
        XCTAssertNil(attestation["platform"])
    }

    func test_reinstall_includesDeviceToken() throws {
        let req = EnrollRequest(
            idempotencyKey: "ik_xyz",
            platform: "ios",
            reason: "reinstall",
            attestation: nil,
            publicKey: "base64key==",
            deviceToken: "dvt_existing"
        )
        let dict = try encodeToDict(req)

        XCTAssertEqual(dict["device_token"] as? String, "dvt_existing")
        XCTAssertEqual(dict["reason"] as? String, "reinstall")
    }
}

// MARK: - VerifyRequest

final class VerifyRequestEncodingTests: XCTestCase {

    func test_allFieldsPresent() throws {
        let req = VerifyRequest(
            deviceToken: "dvt_abc",
            context: "login",
            minimumConfidence: "high"
        )
        let dict = try encodeToDict(req)

        XCTAssertNil(dict["customer_id"])  // no longer sent — server derives from API key
        XCTAssertEqual(dict["device_token"] as? String, "dvt_abc")
        XCTAssertEqual(dict["context"] as? String, "login")
        XCTAssertEqual(dict["minimum_confidence"] as? String, "high")
    }

    func test_minimumConfidence_omittedWhenNil() throws {
        let req = VerifyRequest(
            deviceToken: "dvt_abc",
            context: "signup",
            minimumConfidence: nil
        )
        let dict = try encodeToDict(req)

        XCTAssertNil(dict["minimum_confidence"])
    }
}

// MARK: - FallbackRequest

final class FallbackRequestEncodingTests: XCTestCase {

    func test_includesBothEmailAndHash() throws {
        let req = FallbackRequest(
            deviceToken: "dvt_abc",
            email: "user@example.com",
            emailHash: "sha256hexdigest",
            reason: "biometric_failed"
        )
        let dict = try encodeToDict(req)

        XCTAssertEqual(dict["email"] as? String, "user@example.com")
        XCTAssertEqual(dict["email_hash"] as? String, "sha256hexdigest")
        XCTAssertEqual(dict["device_token"] as? String, "dvt_abc")
        XCTAssertEqual(dict["reason"] as? String, "biometric_failed")
    }

    func test_nullDeviceToken_omitted() throws {
        let req = FallbackRequest(
            deviceToken: nil,
            email: "user@example.com",
            emailHash: "sha256hexdigest",
            reason: "enrollment_failed"
        )
        let dict = try encodeToDict(req)

        XCTAssertNil(dict["device_token"])
    }
}

// MARK: - FallbackCompleteResponse decoding

final class FallbackCompleteResponseDecodingTests: XCTestCase {

    func test_emailDomainAgeDays_decodesNull() throws {
        let json = """
        {
            "verified": true,
            "confidence": "low",
            "session_state": "FALLBACK_COMPLETE",
            "fallback_signals": {
                "ip_consistent": true,
                "disposable_email_domain": false,
                "device_has_prior_verifications": false,
                "email_domain_age_days": null,
                "otp_attempts": 1,
                "time_to_complete_seconds": 42
            }
        }
        """.data(using: .utf8)!

        let response = try decoder.decode(FallbackCompleteResponse.self, from: json)

        XCTAssertTrue(response.verified)
        XCTAssertNil(response.fallbackSignals.emailDomainAgeDays)
        XCTAssertEqual(response.fallbackSignals.otpAttempts, 1)
        XCTAssertEqual(response.fallbackSignals.timeToCompleteSeconds, 42)
    }

    func test_emailDomainAgeDays_decodesInteger() throws {
        let json = """
        {
            "verified": true,
            "confidence": "low",
            "session_state": "FALLBACK_COMPLETE",
            "fallback_signals": {
                "ip_consistent": false,
                "disposable_email_domain": true,
                "device_has_prior_verifications": true,
                "email_domain_age_days": 3650,
                "otp_attempts": 2,
                "time_to_complete_seconds": 90
            }
        }
        """.data(using: .utf8)!

        let response = try decoder.decode(FallbackCompleteResponse.self, from: json)

        XCTAssertEqual(response.fallbackSignals.emailDomainAgeDays, 3650)
    }
}

// MARK: - EnrollResponse decoding

final class EnrollResponseDecodingTests: XCTestCase {

    func test_decodes_serverResponse() throws {
        let json = """
        {
            "device_token": "dvt_abc123",
            "enrolled_at": "2026-04-11T12:00:00Z",
            "status": "active",
            "attestation_verified": true,
            "confidence_ceiling": "high",
            "idempotency_key": "ik_abc"
        }
        """.data(using: .utf8)!

        let response = try decoder.decode(EnrollResponse.self, from: json)

        XCTAssertEqual(response.deviceToken, "dvt_abc123")
        XCTAssertEqual(response.status, "active")
        XCTAssertTrue(response.attestationVerified)
        XCTAssertEqual(response.confidenceCeiling, "high")
        XCTAssertEqual(response.idempotencyKey, "ik_abc")
    }
}
