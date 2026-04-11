import Foundation

/// Top-level error envelope returned by the Vouchflow API.
struct APIErrorResponse: Decodable {
    let error: APIErrorDetail
}

struct APIErrorDetail: Decodable {
    let code: String
    let message: String?
    /// Present on 410 session_expired responses — use this to continue without interruption.
    let retrySessionId: String?
    let retryChallenge: String?
    let expiresAt: Date?
}
