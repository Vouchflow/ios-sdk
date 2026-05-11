import Foundation

/// POST /v1/sign request body (initiate).
struct SignInitiateRequest: Encodable {
    let deviceToken: String
    let context: String
    let canonicalizedPayload: String
    let minimumConfidence: String?
    let idempotencyKey: String

    enum CodingKeys: String, CodingKey {
        case deviceToken = "device_token"
        case context
        case canonicalizedPayload = "canonicalized_payload"
        case minimumConfidence = "minimum_confidence"
        case idempotencyKey = "idempotency_key"
    }
}

/// POST /v1/sign response (initiate).
struct SignInitiateResponse: Decodable {
    let sessionId: String
    let challenge: String        // base64
    let expiresAt: Date
    let payloadSha256: String
}

/// POST /v1/sign/:session_id/complete request body for mobile platforms.
/// `appAttestAssertion` is optional and triggers the iOS high-confidence path.
struct SignCompleteRequest: Encodable {
    let deviceToken: String
    let signedChallenge: String      // base64 DER ECDSA P-256 signature
    let appAttestAssertion: String?  // base64 CBOR assertion (optional)

    enum CodingKeys: String, CodingKey {
        case deviceToken = "device_token"
        case signedChallenge = "signed_challenge"
        case appAttestAssertion = "app_attest_assertion"
    }
}

/// POST /v1/sign/:session_id/complete response.
struct SignCompleteResponse: Decodable {
    let verified: Bool
    let confidence: String
    let deviceToken: String
    let signingDeviceId: String
    let signedAt: Date
    let assertion: String
    let platform: String
    let sessionId: String
}
