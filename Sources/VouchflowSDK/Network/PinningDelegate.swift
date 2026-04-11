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

    init(config: VouchflowConfig) {
        self.config = config
    }

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

        // Check each certificate in the chain against both configured pins
        for i in 0 ..< certificateCount {
            guard let cert = SecTrustGetCertificateAtIndex(serverTrust, i),
                  let spkiHash = spkiSHA256Hash(for: cert) else {
                continue
            }
            if spkiHash == config.leafCertificatePin || spkiHash == config.intermediateCertificatePin {
                completionHandler(.useCredential, URLCredential(trust: serverTrust))
                return
            }
        }

        // No pin matched
        VouchflowLogger.error("[VouchflowSDK] Certificate pinning failure — no pin matched server chain.")
        completionHandler(.cancelAuthenticationChallenge, nil)
    }

    // MARK: - SPKI extraction

    /// Extracts the SubjectPublicKeyInfo from a certificate and returns its SHA-256 hash
    /// as a base64 string, matching the format used in the config pins.
    private func spkiSHA256Hash(for certificate: SecCertificate) -> String? {
        guard let publicKey = SecCertificateCopyKey(certificate),
              let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            return nil
        }

        // We have the raw key bytes. Wrap in a minimal SPKI structure for P-256 keys
        // (the format expected for the pin values) by prepending the EC P-256 SPKI header.
        // This matches what openssl x509 -pubkey produces and what most pin calculators output.
        let spkiHeader = ecP256SPKIHeader()
        var spki = spkiHeader
        spki.append(publicKeyData)

        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        spki.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(spki.count), &digest)
        }
        return Data(digest).base64EncodedString()
    }

    /// DER-encoded SPKI header for EC P-256 public keys.
    /// Sequence { Sequence { OID ecPublicKey, OID prime256v1 }, BitString }
    private func ecP256SPKIHeader() -> Data {
        // Fixed ASN.1 header for EC P-256 SubjectPublicKeyInfo (without the key bytes)
        let header: [UInt8] = [
            0x30, 0x59,              // SEQUENCE, 89 bytes
            0x30, 0x13,              // SEQUENCE, 19 bytes
            0x06, 0x07,              // OID, 7 bytes
            0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,  // ecPublicKey OID
            0x06, 0x08,              // OID, 8 bytes
            0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // prime256v1 OID
            0x03, 0x42,              // BIT STRING, 66 bytes
            0x00,                    // no unused bits
        ]
        return Data(header)
    }
}

// CommonCrypto bridging — available on all Apple platforms without additional imports.
import CommonCrypto
