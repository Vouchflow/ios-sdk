import Foundation
import CryptoKit

/// Signs server-issued challenges with the device's Secure Enclave private key.
final class ChallengeProcessor {

    /// Signs a base64-encoded challenge nonce.
    ///
    /// The challenge arrives from the server as a base64-encoded random nonce. The SDK:
    /// 1. Decodes the base64 to raw bytes.
    /// 2. Signs the raw bytes using ECDSA P-256 with SHA-256 (CryptoKit handles the digest).
    /// 3. Returns the DER-encoded signature as a base64 string.
    ///
    /// - Parameters:
    ///   - challengeBase64: The `challenge` field from `POST /v1/verify` response.
    ///   - privateKey: The device's Secure Enclave private key.
    /// - Returns: Base64-encoded DER signature to send as `signed_challenge`.
    func sign(
        challengeBase64: String,
        with privateKey: SecureEnclave.P256.Signing.PrivateKey
    ) throws -> String {
        guard let challengeData = Data(base64Encoded: challengeBase64) else {
            throw ChallengeError.invalidBase64Challenge
        }

        // CryptoKit's P256.Signing handles SHA-256 hashing internally.
        let signature = try privateKey.signature(for: challengeData)
        return signature.derRepresentation.base64EncodedString()
    }
}

// MARK: - Errors

enum ChallengeError: Error {
    case invalidBase64Challenge
}
