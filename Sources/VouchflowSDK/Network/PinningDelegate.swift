import Foundation
import Security

/// `URLSessionDelegate` that enforces certificate pinning on all Vouchflow API connections.
///
/// Two pins are checked:
/// - **Leaf pin:** SHA-256 of the server's leaf certificate SubjectPublicKeyInfo.
/// - **Intermediate pin:** SHA-256 of the intermediate CA SubjectPublicKeyInfo.
///
/// Either matching is sufficient (OR semantics), which allows zero-downtime leaf rotation:
/// deploy new leaf, intermediate pin continues to pass, rotate leaf pin in next SDK release.
///
/// ## Placeholder pins
/// During development, pins default to `"TODO-..."` values. Behaviour differs by build type:
/// - **Debug:** Pinning is skipped with a runtime warning. Allows testing against the real server
///   before TLS certificates are finalised.
/// - **Release:** All connections are rejected. Do not ship without real pins.
final class PinningDelegate: NSObject, URLSessionDelegate {

    private let config: VouchflowConfig

    /// Records the SPKI hashes the server presented on the most recent pinning failure.
    /// Read from `VouchflowAPIClient` when it catches the resulting `URLError` so the
    /// developer-facing `VouchflowError.pinningFailure` can name what was actually
    /// served (vs. what the SDK was told to pin). Cleared on every fresh challenge.
    private(set) var lastFailureServedSpkiSha256: [String] = []
    private let failureLock = NSLock()

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

        // Placeholder pin handling
        if config.hasTodoPlaceholderPins {
            #if DEBUG
            VouchflowLogger.warn(
                "[VouchflowSDK] Certificate pinning DISABLED — placeholder pins detected. " +
                "Configure real pins before shipping a production build."
            )
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
            #else
            VouchflowLogger.error(
                "[VouchflowSDK] Rejecting connection: placeholder pins in a release build. " +
                "Set real leafCertificatePin and intermediateCertificatePin in VouchflowConfig."
            )
            completionHandler(.cancelAuthenticationChallenge, nil)
            #endif
            return
        }

        // Extract the certificate chain
        let certificateCount = SecTrustGetCertificateCount(serverTrust)
        guard certificateCount > 0 else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // Check each certificate in the chain against both configured pins. Collect the
        // computed SPKI hashes as we go so the failure path can report them — this is
        // what turns the previously-opaque pinningFailure into a self-diagnosing error.
        var served: [String] = []
        for i in 0 ..< certificateCount {
            guard let cert = SecTrustGetCertificateAtIndex(serverTrust, i),
                  let spkiHash = spkiSHA256Hash(for: cert) else {
                continue
            }
            served.append(spkiHash)
            if spkiHash == config.leafCertificatePin || spkiHash == config.intermediateCertificatePin {
                completionHandler(.useCredential, URLCredential(trust: serverTrust))
                return
            }
        }

        // No pin matched — stash the served chain for VouchflowAPIClient to pick up
        // when it constructs the developer-facing VouchflowError.pinningFailure.
        failureLock.lock()
        lastFailureServedSpkiSha256 = served
        failureLock.unlock()
        VouchflowLogger.error(
            "[VouchflowSDK] Certificate pinning failure. Configured: " +
            "[\(config.leafCertificatePin), \(config.intermediateCertificatePin)]. " +
            "Server presented: \(served)."
        )
        completionHandler(.cancelAuthenticationChallenge, nil)
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
