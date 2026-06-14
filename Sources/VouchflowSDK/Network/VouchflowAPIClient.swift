import Foundation

/// HTTP client for all Vouchflow API endpoints.
///
/// Pins API version to `2026-04-01`. SDKs are built against a specific version and the
/// server maintains backwards compatibility within that version per the spec.
final class VouchflowAPIClient {

    private let config: VouchflowConfig
    private let session: URLSession
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    private static let apiVersion = "2026-04-01"

    /// Held strong so we can read `lastFailureServedSpkiSha256` when a pinning challenge
    /// rejects a connection — URLSession only keeps a weak reference to the delegate.
    private let pinningDelegate: PinningDelegate

    init(config: VouchflowConfig) {
        self.config = config

        let pinningDelegate = PinningDelegate(config: config)
        self.pinningDelegate = pinningDelegate
        self.session = URLSession(
            configuration: .ephemeral,
            delegate: pinningDelegate,
            delegateQueue: nil
        )

        self.encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        encoder.dateEncodingStrategy = .iso8601

        self.decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        // Server may return ISO8601 with or without fractional seconds. The
        // built-in .iso8601 strategy (ISO8601DateFormatter with default
        // options) only accepts the "no fractional seconds" form, so a
        // response like 2026-04-30T03:03:07.625Z fails to decode. Try the
        // fractional-seconds variant first, then fall back.
        decoder.dateDecodingStrategy = .custom { decoder in
            let str = try decoder.singleValueContainer().decode(String.self)
            let withFractional = ISO8601DateFormatter()
            withFractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            if let date = withFractional.date(from: str) { return date }
            let plain = ISO8601DateFormatter()
            plain.formatOptions = [.withInternetDateTime]
            if let date = plain.date(from: str) { return date }
            throw DecodingError.dataCorruptedError(
                in: try decoder.singleValueContainer(),
                debugDescription: "Expected date string to be ISO8601-formatted."
            )
        }
    }

    // MARK: - Enrollment

    func enroll(_ request: EnrollRequest) async throws -> EnrollResponse {
        try await perform(method: "POST", path: "/v1/enroll", body: request)
    }

    // MARK: - Verification

    func initiateVerification(_ request: VerifyRequest) async throws -> VerifyResponse {
        try await perform(method: "POST", path: "/v1/verify", body: request)
    }

    func completeVerification(
        sessionId: String,
        _ request: CompleteVerificationRequest
    ) async throws -> CompleteVerificationResponse {
        try await perform(method: "POST", path: "/v1/verify/\(sessionId)/complete", body: request)
    }

    // MARK: - Sign

    func initiateSign(_ request: SignInitiateRequest) async throws -> SignInitiateResponse {
        try await perform(method: "POST", path: "/v1/sign", body: request)
    }

    func completeSign(
        sessionId: String,
        _ request: SignCompleteRequest
    ) async throws -> SignCompleteResponse {
        try await perform(method: "POST", path: "/v1/sign/\(sessionId)/complete", body: request)
    }

    // MARK: - Fallback

    func initiateFallback(
        sessionId: String,
        _ request: FallbackRequest
    ) async throws -> FallbackResponse {
        try await perform(method: "POST", path: "/v1/verify/\(sessionId)/fallback", body: request)
    }

    func completeFallback(
        fallbackSessionId: String,
        _ request: FallbackCompleteRequest
    ) async throws -> FallbackCompleteResponse {
        // OTP submission reuses the complete endpoint, keyed by the fallback session ID.
        try await perform(method: "POST", path: "/v1/verify/\(fallbackSessionId)/complete", body: request)
    }

    // MARK: - Private

    private func perform<RequestBody: Encodable, ResponseBody: Decodable>(
        method: String,
        path: String,
        body: RequestBody
    ) async throws -> ResponseBody {
        let url = endpointURL(path)
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("Bearer \(config.apiKey)", forHTTPHeaderField: "Authorization")
        request.setValue(Self.apiVersion, forHTTPHeaderField: "Vouchflow-API-Version")
        request.httpBody = try encoder.encode(body)

        let (data, response): (Data, URLResponse)
        do {
            (data, response) = try await session.data(for: request)
        } catch let urlError as URLError {
            if urlError.code == .cancelled {
                // URLSession cancels requests when the pinning delegate rejects the challenge.
                // Pull the served chain the delegate stashed at challenge-time so the
                // caller can compare against what they configured. .cancelled can in
                // principle fire for non-pinning reasons (host cancelled the task);
                // we accept the false positive — every code path that reaches here on
                // production traffic is a pinning challenge in practice.
                throw VouchflowError.pinningFailure(
                    hostname: config.environment.baseURL.host ?? "api.vouchflow.dev",
                    configuredPins: [config.leafCertificatePin, config.intermediateCertificatePin],
                    servedSpkiSha256: pinningDelegate.lastFailureServedSpkiSha256
                )
            }
            throw VouchflowError.networkUnavailable
        }

        guard let http = response as? HTTPURLResponse else {
            throw VouchflowError.networkUnavailable
        }

        // Warn on key deprecation — developer should rotate before the deadline.
        if http.value(forHTTPHeaderField: "Vouchflow-Key-Deprecated") == "true" {
            VouchflowLogger.warn(
                "[VouchflowSDK] Your Vouchflow API key is approaching its rotation deadline. " +
                "Rotate your key in the developer dashboard before the deprecation window closes."
            )
        }

        switch http.statusCode {
        case 200 ... 299:
            return try decoder.decode(ResponseBody.self, from: data)

        case 410:
            // Session expired — response body contains retry session data.
            let errorResponse = try decoder.decode(APIErrorResponse.self, from: data)
            let detail = errorResponse.error
            if detail.code == "session_expired",
               let retryId = detail.retrySessionId,
               let retryChallenge = detail.retryChallenge {
                throw VouchflowError.sessionExpired_internal(
                    retrySessionId: retryId,
                    retryChallenge: retryChallenge
                )
            }
            throw VouchflowError.serverError(
                statusCode: http.statusCode,
                code: detail.code,
                message: detail.message
            )

        case 401:
            throw VouchflowError.invalidAPIKey

        default:
            let errorDetail: APIErrorDetail? = try? decoder.decode(APIErrorResponse.self, from: data).error
            let code = errorDetail?.code
            let message = errorDetail?.message

            if code == "verification_impossible" {
                throw VouchflowError.minimumConfidenceUnmet
            }

            // device_not_owned (403): the on-device token belongs to a
            // different App row server-side. Almost always a "two App rows
            // for one product" misconfig; see deviceClaimedElsewhere KDoc for
            // recovery options. Promoting to a typed case lets integrators
            // branch on it cleanly instead of pattern-matching a string code
            // on a generic serverError.
            if http.statusCode == 403 && code == "device_not_owned" {
                throw VouchflowError.deviceClaimedElsewhere
            }

            // public_key_already_registered (409): post-server-v59 this only
            // fires when the public key is claimed under a DIFFERENT customer
            // or app — same-tenant re-token now succeeds upstream. Typed so
            // the integrator's recovery strategy doesn't have to guess.
            if http.statusCode == 409 && code == "public_key_already_registered" {
                throw VouchflowError.publicKeyAlreadyRegistered
            }

            throw VouchflowError.serverError(
                statusCode: http.statusCode,
                code: code,
                message: message
            )
        }
    }

    private func endpointURL(_ path: String) -> URL {
        let relativePath = path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        return URL(string: relativePath, relativeTo: config.environment.baseURL)!.absoluteURL
    }
}

// MARK: - Internal session-expired carrier

extension VouchflowError {
    static func sessionExpired_internal(retrySessionId: String, retryChallenge: String) -> VouchflowError {
        return .__sessionExpiredInternal(retrySessionId: retrySessionId, retryChallenge: retryChallenge)
    }
}
