import Foundation
import Security

/// `URLSessionDelegate` that enforces TLS validation plus certificate pinning on all
/// Vouchflow API connections.
///
/// Order matters, and it is the whole point of this type:
///
/// 1. An SSL policy bound to the SDK's configured host is set on the trust object, and
///    `SecTrustEvaluateWithError` must pass. Expiry, revocation, chain-to-a-trusted-root
///    and hostname are all checked here, by the OS.
/// 2. Only then are the configured SPKI pins applied, as an **additional** constraint.
///
/// Two pins are checked at step 2:
/// - **Leaf pin:** SHA-256 of the server's leaf certificate SubjectPublicKeyInfo.
/// - **Intermediate pin:** SHA-256 of the intermediate CA SubjectPublicKeyInfo.
///
/// Either matching is sufficient (OR semantics), which allows zero-downtime leaf rotation:
/// deploy new leaf, intermediate pin continues to pass, rotate leaf pin in next SDK release.
///
/// Step 1 is not optional and never was safe to omit — see `PinningPolicy` for why an
/// intermediate pin without it accepts any certificate that CA ever issued, for any domain.
///
/// ## Placeholder pins
/// During development, pins default to `"TODO-..."` values. Behaviour differs by build type:
/// - **Debug:** Step 2 is skipped with a runtime warning, so the SDK can be exercised against
///   the real server before TLS pins are finalised. Step 1 still runs.
/// - **Release:** All connections are rejected. Do not ship without real pins.
final class PinningDelegate: NSObject, URLSessionDelegate {

    private let config: VouchflowConfig

    private var lastFailure: PinningRejection?
    private let failureLock = NSLock()

    init(config: VouchflowConfig) {
        self.config = config
    }

    // MARK: - Failure diagnostics

    /// Why the most recent server-trust challenge was rejected, or `nil` if it was accepted.
    /// Read from `VouchflowAPIClient` when it catches the resulting `URLError` so the
    /// developer-facing error can distinguish a chain that failed OS validation from one
    /// that was valid but unpinned. Cleared on every fresh challenge.
    var lastFailureRejection: PinningRejection? {
        failureLock.lock()
        defer { failureLock.unlock() }
        return lastFailure
    }

    /// Records the SPKI hashes the server presented on the most recent **pin-mismatch**
    /// failure, so `VouchflowError.pinningFailure` can name what was actually served (vs.
    /// what the SDK was told to pin). Empty when the last failure was not a pin mismatch —
    /// a chain rejected at trust evaluation never reached pin comparison, and reporting
    /// its hashes as "served pins" would send the reader hunting a stale-pin theory for
    /// what is actually an expired certificate or a hostname mismatch.
    var lastFailureServedSpkiSha256: [String] {
        if case .pinMismatch(let served) = lastFailureRejection {
            return served
        }
        return []
    }

    private func record(_ rejection: PinningRejection?) {
        failureLock.lock()
        lastFailure = rejection
        failureLock.unlock()
    }

    // MARK: - URLSessionDelegate

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        switch decision(forServerTrust: serverTrust) {
        case .accept:
            record(nil)
            completionHandler(.useCredential, URLCredential(trust: serverTrust))

        case .acceptPlaceholderPinsInDebugBuild:
            record(nil)
            VouchflowLogger.warn(
                "[VouchflowSDK] Certificate PINNING disabled — placeholder pins detected. " +
                "Standard TLS chain and hostname validation still applied. " +
                "Configure real pins before shipping a production build."
            )
            completionHandler(.useCredential, URLCredential(trust: serverTrust))

        case .reject(let rejection):
            record(rejection)
            VouchflowLogger.error(logMessage(for: rejection))
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    // MARK: - Decision

    /// Validate first, then pin.
    ///
    /// Split out of the delegate callback (which needs a `URLAuthenticationChallenge` the
    /// tests cannot synthesise) so `PinningDelegateTrustTests` can drive it with real
    /// `SecTrust` objects built from fixture certificates.
    func decision(forServerTrust serverTrust: SecTrust) -> PinningDecision {
        guard let expectedHost = config.environment.baseURL.host else {
            return .reject(.missingExpectedHost)
        }
        // Sequenced deliberately: `evaluateTrust` builds the chain on the trust object, so
        // reading the served certificates afterwards reports the evaluated chain rather
        // than only whatever the caller happened to seed it with.
        let trustEvaluation = evaluateTrust(serverTrust, expectedHost: expectedHost)
        let served = servedSPKIHashes(in: serverTrust)

        return PinningPolicy.decide(
            trustEvaluation: trustEvaluation,
            servedSpkiSha256: served,
            configuredPins: [config.leafCertificatePin, config.intermediateCertificatePin],
            pinsArePlaceholders: config.hasTodoPlaceholderPins,
            allowPlaceholderPinBypass: Self.allowsPlaceholderPinBypass
        )
    }

    /// Debug builds tolerate placeholder pins. This bypasses **pin comparison only**;
    /// `evaluateTrust` runs on every build configuration.
    private static var allowsPlaceholderPinBypass: Bool {
        #if DEBUG
        return true
        #else
        return false
        #endif
    }

    /// Runs the OS chain evaluation with an SSL policy bound to `expectedHost`.
    ///
    /// The hostname argument is what makes this more than a "chains to some trusted root"
    /// check: without it, a certificate legitimately issued for an attacker's own domain
    /// evaluates as perfectly valid.
    private func evaluateTrust(_ serverTrust: SecTrust, expectedHost: String) -> TrustEvaluation {
        let policy = SecPolicyCreateSSL(true, expectedHost as CFString)
        let status = SecTrustSetPolicies(serverTrust, policy)
        guard status == errSecSuccess else {
            return .failed(reason: "could not apply SSL policy for \(expectedHost) (OSStatus \(status))")
        }

        var error: CFError?
        guard SecTrustEvaluateWithError(serverTrust, &error) else {
            let reason = error?.localizedDescription ?? "chain evaluation failed for \(expectedHost)"
            return .failed(reason: reason)
        }
        return .passed
    }

    /// Base64 SHA-256 SPKI hash of every certificate in the presented chain, in chain order.
    /// Certificates whose key type is unsupported are skipped (see `spkiSHA256Hash(for:)`).
    private func servedSPKIHashes(in serverTrust: SecTrust) -> [String] {
        let certificateCount = SecTrustGetCertificateCount(serverTrust)
        var served: [String] = []
        for index in 0 ..< certificateCount {
            guard let cert = SecTrustGetCertificateAtIndex(serverTrust, index),
                  let spkiHash = spkiSHA256Hash(for: cert) else {
                continue
            }
            served.append(spkiHash)
        }
        return served
    }

    private func logMessage(for rejection: PinningRejection) -> String {
        switch rejection {
        case .trustEvaluationFailed(let reason):
            return "[VouchflowSDK] Rejecting connection: TLS chain failed standard validation " +
                "for \(config.environment.baseURL.host ?? "the configured host") — \(reason). " +
                "Certificate pins were not consulted; a chain that cannot be validated is " +
                "not made trustworthy by matching a pin."

        case .pinMismatch(let served):
            return "[VouchflowSDK] Certificate pinning failure. The chain passed standard " +
                "validation but matched no configured pin. Configured: " +
                "[\(config.leafCertificatePin), \(config.intermediateCertificatePin)]. " +
                "Server presented: \(served)."

        case .placeholderPinsInReleaseBuild:
            return "[VouchflowSDK] Rejecting connection: placeholder pins in a release build. " +
                "Set real leafCertificatePin and intermediateCertificatePin in VouchflowConfig."

        case .missingExpectedHost:
            return "[VouchflowSDK] Rejecting connection: could not determine the expected " +
                "hostname from the configured environment, so the TLS chain cannot be " +
                "validated against it."
        }
    }

    // MARK: - SPKI extraction

    /// Extracts the SubjectPublicKeyInfo from a certificate and returns its SHA-256 hash
    /// as a base64 string, matching the format produced by:
    ///
    ///     openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | base64
    ///
    /// Implementation note: `SecKeyCopyExternalRepresentation` returns only the raw key
    /// material (for EC: the uncompressed point `04 || X || Y`), so we have to prepend the
    /// matching SPKI ASN.1 header before hashing. Earlier versions of this SDK hardcoded the
    /// P-256 header, which silently broke pinning for any chain whose intermediate ran on
    /// P-384 — exactly what Let's Encrypt's current YE1 intermediate does. Branch on the
    /// key's actual algorithm + size and use the right header.
    private func spkiSHA256Hash(for certificate: SecCertificate) -> String? {
        guard let publicKey = SecCertificateCopyKey(certificate),
              let attributes = SecKeyCopyAttributes(publicKey) as? [String: Any],
              let keyType = attributes[kSecAttrKeyType as String] as? String,
              let keySizeBits = attributes[kSecAttrKeySizeInBits as String] as? Int,
              let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            return nil
        }

        guard let spkiHeader = spkiHeader(forKeyType: keyType, sizeBits: keySizeBits) else {
            VouchflowLogger.error(
                "[VouchflowSDK] Unsupported certificate key for pinning: type=\(keyType) size=\(keySizeBits). " +
                "Vouchflow's chain currently uses EC P-256 (leaf) + EC P-384 (intermediate); " +
                "if you see this, the server chain changed and this SDK needs an update."
            )
            return nil
        }

        var spki = spkiHeader
        spki.append(publicKeyData)

        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        spki.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(spki.count), &digest)
        }
        return Data(digest).base64EncodedString()
    }

    /// Returns the DER-encoded ASN.1 SPKI header that prefixes the raw public-key bytes
    /// produced by `SecKeyCopyExternalRepresentation`. Returns nil for unsupported types.
    private func spkiHeader(forKeyType keyType: String, sizeBits: Int) -> Data? {
        let isEC = (keyType == (kSecAttrKeyTypeECSECPrimeRandom as String) ||
                    keyType == (kSecAttrKeyTypeEC as String))
        guard isEC else { return nil }
        switch sizeBits {
        case 256: return Self.ecP256SPKIHeader
        case 384: return Self.ecP384SPKIHeader
        default:  return nil
        }
    }

    /// DER ASN.1 SPKI header for EC P-256 (prime256v1).
    /// SEQUENCE { AlgorithmIdentifier { OID ecPublicKey, OID prime256v1 }, BIT STRING {…} }
    /// where the BIT STRING wraps the 65-byte uncompressed EC point (04 || X[32] || Y[32]).
    private static let ecP256SPKIHeader = Data([
        0x30, 0x59,                              // SEQUENCE, 89 bytes
        0x30, 0x13,                              //   SEQUENCE, 19 bytes
        0x06, 0x07,                              //     OID, 7 bytes
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,//       ecPublicKey (1.2.840.10045.2.1)
        0x06, 0x08,                              //     OID, 8 bytes
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, //   prime256v1 (1.2.840.10045.3.1.7)
        0x03, 0x42,                              //   BIT STRING, 66 bytes
        0x00,                                    //     no unused bits
    ])

    /// DER ASN.1 SPKI header for EC P-384 (secp384r1).
    /// Same shape as P-256 but with a 97-byte point (04 || X[48] || Y[48]).
    /// Without this branch, the SDK would hash (P-256 header || P-384 point) and produce
    /// digests that can never match any real certificate's SPKI — silently breaking the
    /// intermediate pin, which is the whole "zero-downtime leaf rotation" mechanism.
    private static let ecP384SPKIHeader = Data([
        0x30, 0x76,                              // SEQUENCE, 118 bytes
        0x30, 0x10,                              //   SEQUENCE, 16 bytes
        0x06, 0x07,                              //     OID, 7 bytes
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,//       ecPublicKey (1.2.840.10045.2.1)
        0x06, 0x05,                              //     OID, 5 bytes
        0x2B, 0x81, 0x04, 0x00, 0x22,            //       secp384r1 (1.3.132.0.34)
        0x03, 0x62,                              //   BIT STRING, 98 bytes
        0x00,                                    //     no unused bits
    ])
}

// CommonCrypto bridging — available on all Apple platforms without additional imports.
import CommonCrypto
