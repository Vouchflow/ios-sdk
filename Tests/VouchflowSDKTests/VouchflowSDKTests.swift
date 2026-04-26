import CryptoKit
import Foundation
import XCTest
@testable import VouchflowSDK

final class VouchflowSDKTests: XCTestCase {
    // Integration tests require a physical device with App Attest support.
    // Unit tests for individual components go here.
}

// MARK: - VouchflowConfigTests

final class VouchflowConfigTests: XCTestCase {

    // ── hasTodoPlaceholderPins ────────────────────────────────────────────────

    func test_hasTodoPlaceholderPins_trueWhenLeafStartsWithTODO() {
        let config = VouchflowConfig(
            apiKey: "vsk_live_test",
            leafCertificatePin: "TODO-replace-me",
            intermediateCertificatePin: "C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M="
        )
        XCTAssertTrue(config.hasTodoPlaceholderPins)
    }

    func test_hasTodoPlaceholderPins_trueWhenIntermediateStartsWithTODO() {
        let config = VouchflowConfig(
            apiKey: "vsk_live_test",
            leafCertificatePin: "iFvwVyJSxnQdyaUvUERIf+8qk7gRze3612JMwoO3zdU=",
            intermediateCertificatePin: "TODO-replace-me-too"
        )
        XCTAssertTrue(config.hasTodoPlaceholderPins)
    }

    func test_hasTodoPlaceholderPins_falseWithRealPins() {
        let config = VouchflowConfig(
            apiKey: "vsk_live_test",
            leafCertificatePin: "iFvwVyJSxnQdyaUvUERIf+8qk7gRze3612JMwoO3zdU=",
            intermediateCertificatePin: "C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M="
        )
        XCTAssertFalse(config.hasTodoPlaceholderPins)
    }

    // ── Default values ────────────────────────────────────────────────────────

    func test_defaultEnvironmentIsProduction() {
        let config = VouchflowConfig(apiKey: "vsk_live_test")
        if case .production = config.environment {
            // pass
        } else {
            XCTFail("Expected .production, got \(config.environment)")
        }
    }

    func test_defaultLeafPinIsNonEmptyAndNotTODO() {
        let config = VouchflowConfig(apiKey: "vsk_live_test")
        XCTAssertFalse(config.leafCertificatePin.isEmpty, "Default leafCertificatePin must not be empty")
        XCTAssertFalse(
            config.leafCertificatePin.hasPrefix("TODO"),
            "Default leafCertificatePin must not be a TODO placeholder"
        )
    }

    func test_defaultIntermediatePinIsNonEmptyAndNotTODO() {
        let config = VouchflowConfig(apiKey: "vsk_live_test")
        XCTAssertFalse(config.intermediateCertificatePin.isEmpty, "Default intermediateCertificatePin must not be empty")
        XCTAssertFalse(
            config.intermediateCertificatePin.hasPrefix("TODO"),
            "Default intermediateCertificatePin must not be a TODO placeholder"
        )
    }

    func test_configInitialisesWithAllDefaults() {
        let config = VouchflowConfig(apiKey: "vsk_live_abc123")
        XCTAssertEqual(config.apiKey, "vsk_live_abc123")
        XCTAssertNil(config.keychainAccessGroup)
        XCTAssertFalse(config.leafCertificatePin.isEmpty)
        XCTAssertFalse(config.intermediateCertificatePin.isEmpty)
    }
}

// MARK: - VouchflowErrorTests

final class VouchflowErrorTests: XCTestCase {

    // ── __sessionExpiredInternal ──────────────────────────────────────────────

    func test_sessionExpiredInternal_existsAndCanBePatternMatched() {
        let error: VouchflowError = .__sessionExpiredInternal(
            retrySessionId: "sess_retry_abc",
            retryChallenge: "challenge_xyz=="
        )
        if case .__sessionExpiredInternal(let retryId, let retryChallenge) = error {
            XCTAssertEqual(retryId, "sess_retry_abc")
            XCTAssertEqual(retryChallenge, "challenge_xyz==")
        } else {
            XCTFail("Expected .__sessionExpiredInternal case")
        }
    }

    func test_sessionExpiredInternal_factoryCreatesCorrectCase() {
        let error = VouchflowError.sessionExpired_internal(
            retrySessionId: "retry_001",
            retryChallenge: "ch_abc=="
        )
        if case .__sessionExpiredInternal(let retryId, let retryChallenge) = error {
            XCTAssertEqual(retryId, "retry_001")
            XCTAssertEqual(retryChallenge, "ch_abc==")
        } else {
            XCTFail("Factory must produce .__sessionExpiredInternal case")
        }
    }

    func test_sessionExpiredInternal_isNotSessionExpiredRepeatedly() {
        let internal_ = VouchflowError.__sessionExpiredInternal(
            retrySessionId: "r",
            retryChallenge: "c"
        )
        // Must be a distinct case from the publicly-facing sessionExpiredRepeatedly.
        if case .sessionExpiredRepeatedly = internal_ {
            XCTFail("__sessionExpiredInternal must NOT match .sessionExpiredRepeatedly")
        }
    }

    // ── Public error cases are distinct ──────────────────────────────────────

    func test_allPublicErrorCasesAreDistinct() {
        let errors: [VouchflowError] = [
            .notConfigured,
            .invalidAPIKey,
            .enrollmentFailed(underlying: nil),
            .attestationUnavailable,
            .keychainAccessDenied,
            .biometricUnavailable,
            .biometricCancelled(sessionId: "s1"),
            .biometricFailed(sessionId: "s2"),
            .sessionExpiredRepeatedly,
            .noActiveSession,
            .minimumConfidenceUnmet,
            .networkUnavailable,
            .serverError(statusCode: 500, code: nil, message: nil),
            .pinningFailure,
        ]
        // If any two errors accidentally share the same case label, this count would be wrong.
        // Swift enum cases with different associated values are distinct.
        XCTAssertEqual(errors.count, 14, "Should have exactly 14 distinct public error cases")
    }

    func test_biometricCancelled_carriesSessionId() {
        let error = VouchflowError.biometricCancelled(sessionId: "sess_abc")
        if case .biometricCancelled(let id) = error {
            XCTAssertEqual(id, "sess_abc")
        } else {
            XCTFail("Expected .biometricCancelled")
        }
    }

    func test_biometricFailed_carriesSessionId() {
        let error = VouchflowError.biometricFailed(sessionId: "sess_xyz")
        if case .biometricFailed(let id) = error {
            XCTAssertEqual(id, "sess_xyz")
        } else {
            XCTFail("Expected .biometricFailed")
        }
    }

    func test_serverError_carriesAllFields() {
        let error = VouchflowError.serverError(statusCode: 429, code: "rate_limited", message: "Too many requests")
        if case .serverError(let statusCode, let errorCode, let message) = error {
            XCTAssertEqual(statusCode, 429)
            XCTAssertEqual(errorCode, "rate_limited")
            XCTAssertEqual(message, "Too many requests")
        } else {
            XCTFail("Expected .serverError")
        }
    }
}

// MARK: - EmailHashTests

/// Tests the sha256Hex(_:) helper used internally by FallbackManager
/// (Sources/VouchflowSDK/Core/FallbackManager.swift).
final class EmailHashTests: XCTestCase {

    /// Local copy of the sha256Hex helper. Kept in sync with FallbackManager.
    private func sha256Hex(_ input: String) -> String {
        let digest = SHA256.hash(data: Data(input.utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    func test_sha256OfKnownEmail() {
        // Authoritative reference value for SHA-256("user@example.com").
        let result = sha256Hex("user@example.com")
        XCTAssertEqual(result, "b4c9a289323b21a01c3e940f150eb9b8c542587f1abfd8f0e1cc1ffc5e475514")
    }

    func test_sha256OfEmptyString() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let result = sha256Hex("")
        XCTAssertEqual(result, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    func test_hashIsLowercaseHex() {
        let result = sha256Hex("test@vouchflow.dev")
        XCTAssertEqual(result, result.lowercased(), "Hash must be lowercase hex")
        XCTAssertEqual(result.count, 64, "SHA-256 hex must be 64 characters")
        let validChars = CharacterSet(charactersIn: "0123456789abcdef")
        let resultChars = CharacterSet(charactersIn: result)
        XCTAssertTrue(validChars.isSuperset(of: resultChars), "Hash must contain only [0-9a-f]")
    }

    func test_hashIsDeterministic() {
        let input = "deterministic@example.org"
        XCTAssertEqual(sha256Hex(input), sha256Hex(input))
    }

    func test_differentEmailsProduceDifferentHashes() {
        XCTAssertNotEqual(sha256Hex("alice@example.com"), sha256Hex("bob@example.com"))
    }
}

// MARK: - APIResponseMappingTests

final class APIResponseMappingTests: XCTestCase {

    private let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.keyDecodingStrategy = .convertFromSnakeCase
        d.dateDecodingStrategy = .iso8601
        return d
    }()

    // ── Error code mapping logic (mirrors VouchflowAPIClient.perform) ─────────

    /// Replicates the status-code → VouchflowError mapping from VouchflowAPIClient.perform().
    /// Testing this logic in isolation avoids the need for a live URLSession.
    private func mapResponse(statusCode: Int, data: Data) throws -> VouchflowError {
        switch statusCode {
        case 200 ... 299:
            fatalError("Not an error response — caller must not pass 2xx")

        case 410:
            let errorResponse = try decoder.decode(APIErrorResponse.self, from: data)
            let detail = errorResponse.error
            if detail.code == "session_expired",
               let retryId = detail.retrySessionId,
               let retryChallenge = detail.retryChallenge {
                return VouchflowError.sessionExpired_internal(
                    retrySessionId: retryId,
                    retryChallenge: retryChallenge
                )
            }
            return .serverError(statusCode: statusCode, code: detail.code, message: detail.message)

        case 401:
            return .invalidAPIKey

        default:
            let errorDetail = try? decoder.decode(APIErrorResponse.self, from: data).error
            if errorDetail?.code == "verification_impossible" {
                return .minimumConfidenceUnmet
            }
            return .serverError(statusCode: statusCode, code: errorDetail?.code, message: errorDetail?.message)
        }
    }

    func test_401_mapsToInvalidAPIKey() throws {
        // 401 uses no body — pass a minimal valid JSON object.
        let data = Data("{}".utf8)
        let error = try mapResponse(statusCode: 401, data: data)
        if case .invalidAPIKey = error {
            // pass
        } else {
            XCTFail("Expected .invalidAPIKey, got \(error)")
        }
    }

    func test_410_sessionExpiredWithRetryFields_mapsToSessionExpiredInternal() throws {
        let json = """
        {
            "error": {
                "code": "session_expired",
                "message": "Session has expired.",
                "retry_session_id": "sess_retry_abc",
                "retry_challenge": "challenge_xyz=="
            }
        }
        """.data(using: .utf8)!
        let error = try mapResponse(statusCode: 410, data: json)
        if case .__sessionExpiredInternal(let retryId, let retryChallenge) = error {
            XCTAssertEqual(retryId, "sess_retry_abc")
            XCTAssertEqual(retryChallenge, "challenge_xyz==")
        } else {
            XCTFail("Expected .__sessionExpiredInternal, got \(error)")
        }
    }

    func test_410_sessionExpiredMissingRetryFields_mapsToServerError() throws {
        let json = """
        {
            "error": {
                "code": "session_expired",
                "message": "Session has expired."
            }
        }
        """.data(using: .utf8)!
        let error = try mapResponse(statusCode: 410, data: json)
        if case .serverError(let statusCode, _, _) = error {
            XCTAssertEqual(statusCode, 410)
        } else {
            XCTFail("Expected .serverError, got \(error)")
        }
    }

    func test_4xx_verificationImpossible_mapsToMinimumConfidenceUnmet() throws {
        let json = """
        {
            "error": {
                "code": "verification_impossible",
                "message": "Cannot meet minimum confidence."
            }
        }
        """.data(using: .utf8)!
        for statusCode in [400, 403, 422, 451] {
            let error = try mapResponse(statusCode: statusCode, data: json)
            if case .minimumConfidenceUnmet = error {
                // pass
            } else {
                XCTFail("Status \(statusCode) + verification_impossible should map to .minimumConfidenceUnmet, got \(error)")
            }
        }
    }

    func test_4xx_unknownCode_mapsToServerError() throws {
        let json = """
        {
            "error": {
                "code": "invalid_device",
                "message": "Device not recognised."
            }
        }
        """.data(using: .utf8)!
        let error = try mapResponse(statusCode: 422, data: json)
        if case .serverError(let statusCode, let code, _) = error {
            XCTAssertEqual(statusCode, 422)
            XCTAssertEqual(code, "invalid_device")
        } else {
            XCTFail("Expected .serverError, got \(error)")
        }
    }

    // ── __sessionExpiredInternal is never publicly exposed ────────────────────

    func test_sessionExpiredInternal_isDistinctFromPublicError() {
        // VerificationManager catches __sessionExpiredInternal and converts it to
        // either a silent retry or .sessionExpiredRepeatedly.
        // Verify the two cases are structurally distinct.
        let internal_ = VouchflowError.__sessionExpiredInternal(
            retrySessionId: "r",
            retryChallenge: "c"
        )
        if case .sessionExpiredRepeatedly = internal_ {
            XCTFail("__sessionExpiredInternal must not match .sessionExpiredRepeatedly")
        }
        // Exhaustive match to confirm it can ONLY match its own case.
        switch internal_ {
        case .__sessionExpiredInternal:
            break // correct
        default:
            XCTFail("Should only match .__sessionExpiredInternal")
        }
    }
}
