import Foundation

// MARK: - Initiate verification

struct VerifyRequest: Encodable {
    let customerId: String
    let deviceToken: String
    let context: String
    /// Optional. If the device cannot reach this level, the server returns `verification_impossible`.
    let minimumConfidence: String?
}

struct VerifyResponse: Decodable {
    let sessionId: String
    let challenge: String
    let expiresAt: Date
    let sessionState: String
}

// MARK: - Complete verification (primary path)

struct CompleteVerificationRequest: Encodable {
    let deviceToken: String
    let signedChallenge: String
    let biometricUsed: Bool
}

struct CompleteVerificationResponse: Decodable {
    let verified: Bool
    let confidence: String
    let sessionState: String
    let deviceToken: String
    let deviceAgeDays: Int
    let networkVerifications: Int
    let firstSeen: Date?
    let signals: SignalsPayload
    let fallbackUsed: Bool
    let context: String

    struct SignalsPayload: Decodable {
        let keychainPersistent: Bool
        let biometricUsed: Bool
        let crossAppHistory: Bool
        let anomalyFlags: [String]
        let attestationVerified: Bool
    }
}
