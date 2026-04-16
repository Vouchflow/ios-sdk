import Foundation

// MARK: - Request

struct EnrollRequest: Encodable {
    let idempotencyKey: String
    let platform: String
    /// The enrollment reason. Maps to spec values: fresh_enrollment, reinstall, key_invalidated, corrupted.
    let reason: String
    let attestation: AttestationPayload?
    let publicKey: String
    /// Existing device token on reinstall; omitted (nil) on fresh enrollment.
    let deviceToken: String?

    struct AttestationPayload: Encodable {
        let token: String
        let keyId: String
    }
}

// MARK: - Response

struct EnrollResponse: Decodable {
    let deviceToken: String
    let enrolledAt: Date
    let status: String
    let attestationVerified: Bool
    let confidenceCeiling: String
    let idempotencyKey: String
}
