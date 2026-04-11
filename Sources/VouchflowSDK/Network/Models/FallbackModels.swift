import Foundation

// MARK: - Initiate fallback

struct FallbackRequest: Encodable {
    let deviceToken: String?
    /// Plain-text email address — required by the server for OTP delivery.
    let email: String
    /// SHA-256 hex digest of the user's email address, used by the server for rate limiting.
    let emailHash: String
    let reason: String
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
    let fallbackSignals: FallbackSignalsPayload

    struct FallbackSignalsPayload: Decodable {
        let ipConsistent: Bool
        let disposableEmailDomain: Bool
        let deviceHasPriorVerifications: Bool
        let emailDomainAgeDays: Int?
        let otpAttempts: Int
        let timeToCompleteSeconds: Int
    }
}
