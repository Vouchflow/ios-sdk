import Foundation

// MARK: - Initiate fallback

enum FallbackRequest: Encodable {
    case email(deviceToken: String?, email: String, emailHash: String, reason: String)
    case reviewerCode(deviceToken: String, code: String)

    // Preserve the existing email request construction and wire format.
    init(deviceToken: String?, email: String, emailHash: String, reason: String) {
        self = .email(deviceToken: deviceToken, email: email, emailHash: emailHash, reason: reason)
    }

    private enum CodingKeys: String, CodingKey {
        case deviceToken, email, emailHash, reason, method, reviewerCode
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case let .email(deviceToken, email, emailHash, reason):
            try container.encodeIfPresent(deviceToken, forKey: .deviceToken)
            try container.encode(email, forKey: .email)
            try container.encode(emailHash, forKey: .emailHash)
            try container.encode(reason, forKey: .reason)
        case let .reviewerCode(deviceToken, code):
            try container.encode(deviceToken, forKey: .deviceToken)
            try container.encode("reviewer_code", forKey: .method)
            try container.encode(code, forKey: .reviewerCode)
        }
    }
}

struct FallbackResponse: Decodable {
    let fallbackSessionId: String
    let method: String
    let expiresAt: Date
    let sessionState: String
}

// MARK: - Complete fallback (OTP submission)
//
// The OTP submission goes to POST /v1/verify/{fallbackSessionId}/complete per the spec
// ("fallback OTP submission uses same endpoint"). The fallbackSessionId from FallbackResponse
// is used as the path parameter — not the original session_id.

struct FallbackCompleteRequest: Encodable {
    let otp: String
    let deviceToken: String?
}

struct FallbackCompleteResponse: Decodable {
    let verified: Bool
    let confidence: String
    let sessionState: String
    let fallbackSignals: FallbackSignalsPayload?

    private enum CodingKeys: String, CodingKey {
        case verified, confidence, sessionState, fallbackSignals, fallbackMethod
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        verified = try container.decode(Bool.self, forKey: .verified)
        confidence = try container.decode(String.self, forKey: .confidence)
        sessionState = try container.decode(String.self, forKey: .sessionState)
        let method = try container.decodeIfPresent(String.self, forKey: .fallbackMethod)
        if method == "reviewer_code" {
            fallbackSignals = nil
        } else {
            // Keep email OTP's existing required-signal decoding contract.
            fallbackSignals = try container.decode(FallbackSignalsPayload.self, forKey: .fallbackSignals)
        }
    }

    struct FallbackSignalsPayload: Decodable {
        let ipConsistent: Bool
        let disposableEmailDomain: Bool
        let deviceHasPriorVerifications: Bool
        let emailDomainAgeDays: Int?
        let otpAttempts: Int
        let timeToCompleteSeconds: Int
    }
}
