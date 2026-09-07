import Foundation
import Security

/// `URLSessionTaskDelegate` that enforces TLS validation plus certificate pinning on all
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
final class PinningDelegate: NSObject, URLSessionTaskDelegate {

    private let config: VouchflowConfig

    private var lastFailure: PinningRejection?
    private let failureLock = NSLock()

    init(config: VouchflowConfig) {
        self.config = config
    }

    // MARK: - Failure diagnostics

    /// Why this task's server-trust challenge was rejected, or `nil` if it was accepted.
    /// Read from `VouchflowAPIClient` when it catches the resulting `URLError` so the
    /// developer-facing error can distinguish a chain that failed OS validation from one
    /// that was valid but unpinned. Cleared when a server-trust challenge is accepted.
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

    // MARK: - URLSessionTaskDelegate

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
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
        if let preflightDecision = PinningPolicy.preflightDecision(
            pinsArePlaceholders: config.hasTodoPlaceholderPins,
            allowPlaceholderPinBypass: Self.allowsPlaceholderPinBypass
        ) {
            return preflightDecision
        }

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
    /// Implementation note: `SecKeyCopyExternalRepresentation` returns only raw key
    /// material, and its shape depends on the algorithm: for EC it is the uncompressed point
    /// `04 || X || Y` (complete except for the SPKI header — see `spkiBytes`), while for RSA
    /// it is not DER — the documented form is `[len][modulus][len][exponent]`, which must be
    /// re-assembled into a full SPKI (see `rsaSPKI`), and `rsaSPKI` additionally accepts
    /// already-DER RSA data in case a platform reports that form instead. Dispatch is on
    /// the key-type attribute, but every form that attribute is observed to take is
    /// accepted (see `isRSAKeyType`): `kSecAttrKeyType` is not a stable discriminator —
    /// it has been seen as the bare algorithm id `"42"` for RSA keys, so comparing it
    /// against the documented constant alone silently routed every RSA certificate to the
    /// unsupported-skip path. Earlier versions of this SDK hardcoded the P-256 header,
    /// which silently broke pinning for any chain whose intermediate ran on P-384 —
    /// exactly what Let's Encrypt's current YE1 intermediate does.
    ///
    /// Internal (not `private`) so the test target can hash fixture certificates directly
    /// via `@testable import` and compare against openssl-derived values; the end-to-end
    /// `decision(forServerTrust:)` tests can only assert accept/reject, not the exact hash.
    func spkiSHA256Hash(for certificate: SecCertificate) -> String? {
        guard let publicKey = SecCertificateCopyKey(certificate),
              let attributes = SecKeyCopyAttributes(publicKey) as? [String: Any],
              let keyType = attributes[kSecAttrKeyType as String] as? String,
              let keySizeBits = attributes[kSecAttrKeySizeInBits as String] as? Int,
              let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            return nil
        }

        guard let spki = spkiBytes(forKeyType: keyType, sizeBits: keySizeBits, externalKeyData: publicKeyData) else {
            // Include the external representation's shape so a report discriminates
            // between the candidate RSA layouts without further test machinery.
            let externalHex = publicKeyData.prefix(8)
                .map { String(format: "%02x", $0) }
                .joined(separator: " ")
            VouchflowLogger.error(
                "[VouchflowSDK] Unsupported certificate key for pinning: type=\(keyType) size=\(keySizeBits). " +
                "External representation: \(publicKeyData.count) bytes starting [\(externalHex)]. " +
                "Supported: EC P-256/P-384 and RSA 2048/3072/4096. " +
                "If you see this, the server chain changed and this SDK needs an update."
            )
            return nil
        }

        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        spki.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(spki.count), &digest)
        }
        return Data(digest).base64EncodedString()
    }

    /// Full DER SPKI bytes for a key of the given size, from Apple's external
    /// representation. Dispatch is on the **key-type attribute**, accepting every form
    /// that attribute is observed to take for RSA keys (see `isRSAKeyType`): comparing
    /// against the documented constant alone silently routed every RSA certificate to
    /// the unsupported-skip path on platforms where `kSecAttrKeyType` reads "42" (the
    /// raw algorithm id). The RSA external byte layout is itself not assumed — `rsaSPKI`
    /// accepts both candidate layouts and rejects anything that does not actually encode
    /// an RSA key of the given size. EC keys keep the unchanged `header || raw point`
    /// path via `spkiHeader`, which rejects every RSA key-type form, so no EC key can
    /// reach the RSA path. Returns nil for unsupported keys, which the caller logs
    /// (including the external bytes' shape) and skips — a skip, never a crash.
    private func spkiBytes(forKeyType keyType: String, sizeBits: Int, externalKeyData: Data) -> Data? {
        if Self.isRSAKeyType(keyType) {
            return Self.rsaSPKI(sizeBits: sizeBits, externalKeyData: externalKeyData)
        }
        guard let header = spkiHeader(forKeyType: keyType, sizeBits: sizeBits) else { return nil }
        var spki = header
        spki.append(externalKeyData)
        return spki
    }

    /// Every form `kSecAttrKeyType` is observed to take for RSA keys: the documented
    /// constant as a String, the bare algorithm id `"42"`, and the algorithm's common
    /// name `"RSA"`. EC keys are matched separately by `spkiHeader`.
    private static func isRSAKeyType(_ keyType: String) -> Bool {
        keyType == (kSecAttrKeyTypeRSA as String) || keyType == "42" || keyType == "RSA"
    }

    /// Returns the DER-encoded ASN.1 SPKI header that prefixes the raw public-key bytes
    /// produced by `SecKeyCopyExternalRepresentation` — EC types only (RSA keys are
    /// dispatched earlier on the key-type attribute, by `spkiBytes`, and take the
    /// re-assembly path in `rsaSPKI` rather than a fixed header). Returns nil for
    /// unsupported types and sizes.
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

    // MARK: - RSA SPKI assembly

    /// DER AlgorithmIdentifier for rsaEncryption (1.2.840.113549.1.1.1) with NULL parameters.
    /// Identical for every RSA key size.
    private static let rsaEncryptionAlgorithmIdentifier = Data([
        0x30, 0x0D,                              // SEQUENCE, 13 bytes
        0x06, 0x09,                              //   OID, 9 bytes
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, //   rsaEncryption
        0x05, 0x00,                              //   NULL
    ])

    /// The AlgorithmIdentifier's content — its SEQUENCE wrapper stripped — used to
    /// recognize an rsaEncryption AlgorithmIdentifier while parsing DER.
    private static let rsaEncryptionAlgorithmIdentifierContent = Data([
        0x06, 0x09,                              //   OID, 9 bytes
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, //   rsaEncryption
        0x05, 0x00,                              //   NULL
    ])

    /// Assembles the full DER SubjectPublicKeyInfo for an RSA public key of a supported
    /// size. Two external-representation layouts are accepted, and whichever is taken
    /// must actually encode an RSA key of `sizeBits`, so a misrouted EC point or
    /// unrelated DER can never be hashed as an RSA SPKI:
    ///
    /// - The documented non-DER form
    ///   `[4-byte big-endian modulus byte count][modulus][4-byte big-endian exponent
    ///   byte count][exponent]`: the length prefixes are stripped and the INTEGER
    ///   payloads re-wrapped with proper DER lengths (the modulus blob already carries
    ///   the leading 0x00 DER requires when the high bit is set, so it is a valid
    ///   INTEGER payload as-is).
    /// - DER beginning `0x30`: either a full SubjectPublicKeyInfo (rsaEncryption
    ///   AlgorithmIdentifier, BIT STRING payload = RSAPublicKey), returned as-is once
    ///   validated, or a bare RSAPublicKey SEQUENCE, re-wrapped in the rsaEncryption
    ///   AlgorithmIdentifier + BIT STRING so the hash is identical either way.
    ///
    /// Supported sizes: 2048, 3072, 4096 — the sizes of real deployment roots (ISRG Root X1
    /// is RSA 4096). Anything else returns nil and is skipped with a log, never a crash.
    private static func rsaSPKI(sizeBits: Int, externalKeyData: Data) -> Data? {
        guard [2048, 3072, 4096].contains(sizeBits) else { return nil }
        let bytes = [UInt8](externalKeyData)
        if bytes.first == 0x30 {
            return derSPKI(bytes, sizeBits: sizeBits)
        }
        return prefixedSPKI(bytes, sizeBits: sizeBits)
    }

    /// Assembles the SPKI from the length-prefixed (non-DER) external representation.
    private static func prefixedSPKI(_ bytes: [UInt8], sizeBits: Int) -> Data? {
        let expectedModulusBytes = sizeBits / 8
        guard bytes.count > 8 else { return nil }

        let modulusByteCount = bigEndianUInt32(bytes.prefix(4))
        // Apple prepends a 0x00 exactly when the modulus's high bit is set, so both
        // sizeBits/8 and sizeBits/8 + 1 bytes are legitimate for a sizeBits-bit key.
        guard modulusByteCount == expectedModulusBytes || modulusByteCount == expectedModulusBytes + 1 else {
            return nil
        }
        let modulus = Array(bytes.dropFirst(4).prefix(modulusByteCount))
        guard modulus.count == modulusByteCount else { return nil }

        let exponentField = bytes.dropFirst(4 + modulusByteCount)
        let exponentByteCount = bigEndianUInt32(exponentField.prefix(4))
        // Require the exponent field to account for every remaining byte, so the RSA
        // structural signature is exact and nothing but genuine RSA external data can
        // be re-assembled as one.
        guard exponentByteCount > 0, exponentField.count == 4 + exponentByteCount else { return nil }
        let exponent = Array(exponentField.dropFirst(4).prefix(exponentByteCount))

        return spkiFromRSAPublicKey(modulus: modulus, exponent: exponent)
    }

    /// Parses DER starting `0x30` as RSA key material: either a full SubjectPublicKeyInfo
    /// (returned as-is once validated) or a bare RSAPublicKey SEQUENCE (re-wrapped
    /// canonically). Returns nil unless the data encodes rsaEncryption with an
    /// RSAPublicKey whose modulus is a `sizeBits`-bit value, so non-RSA DER can never be
    /// hashed as an RSA SPKI.
    private static func derSPKI(_ bytes: [UInt8], sizeBits: Int) -> Data? {
        guard let outer = derTLV(bytes), outer.tag == 0x30 else { return nil }

        // SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey BIT STRING }
        if let algorithm = derTLV(outer.content),
           algorithm.tag == 0x30,
           Data(algorithm.content) == rsaEncryptionAlgorithmIdentifierContent,
           let bitString = derTLV(Array(outer.content[algorithm.totalLength...])),
           bitString.tag == 0x03,
           bitString.content.first == 0x00,
           algorithm.totalLength + bitString.totalLength == outer.content.count,
           let publicKey = derTLV(Array(bitString.content.dropFirst(1))),
           publicKey.tag == 0x30,
           rsaIntegerPayloads(publicKey.content, sizeBits: sizeBits) != nil {
            return Data(bytes)
        }

        // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
        if let payloads = rsaIntegerPayloads(outer.content, sizeBits: sizeBits) {
            return spkiFromRSAPublicKey(modulus: payloads.modulus, exponent: payloads.exponent)
        }

        return nil
    }

    /// INTEGER payloads of an RSAPublicKey SEQUENCE's content (modulus, exponent), or
    /// nil unless exactly two INTEGERs consume the whole content and the modulus is a
    /// `sizeBits`-bit value (DER's minimal encoding gives sizeBits/8 or sizeBits/8 + 1
    /// payload bytes — the extra one is the leading 0x00 when the high bit is set).
    private static func rsaIntegerPayloads(_ content: [UInt8], sizeBits: Int) -> (modulus: [UInt8], exponent: [UInt8])? {
        guard let modulusTLV = derTLV(content),
              modulusTLV.tag == 0x02,
              !modulusTLV.content.isEmpty else { return nil }
        let expectedModulusBytes = sizeBits / 8
        guard modulusTLV.content.count == expectedModulusBytes || modulusTLV.content.count == expectedModulusBytes + 1 else {
            return nil
        }
        guard let exponentTLV = derTLV(Array(content[modulusTLV.totalLength...])),
              exponentTLV.tag == 0x02,
              !exponentTLV.content.isEmpty,
              modulusTLV.totalLength + exponentTLV.totalLength == content.count else { return nil }
        return (modulusTLV.content, exponentTLV.content)
    }

    /// Canonical DER SubjectPublicKeyInfo for an RSA key from its INTEGER payloads.
    /// The INTEGERs are built first so the SEQUENCE lengths cover their full encodings
    /// (a 257-byte RSA modulus needs a long-form DER length — getting this wrong shifts
    /// every byte after the header and breaks the hash).
    private static func spkiFromRSAPublicKey(modulus: [UInt8], exponent: [UInt8]) -> Data {
        let modulusInteger = Data([0x02]) + derLength(modulus.count) + Data(modulus)
        let exponentInteger = Data([0x02]) + derLength(exponent.count) + Data(exponent)
        var rsaPublicKey = Data([0x30])
        rsaPublicKey.append(contentsOf: derLength(modulusInteger.count + exponentInteger.count))
        rsaPublicKey.append(modulusInteger)
        rsaPublicKey.append(exponentInteger)

        var body = rsaEncryptionAlgorithmIdentifier
        body.append(0x03)                                    // BIT STRING
        body.append(contentsOf: derLength(rsaPublicKey.count + 1))
        body.append(0x00)                                    // no unused bits
        body.append(rsaPublicKey)

        var spki = Data([0x30])
        spki.append(contentsOf: derLength(body.count))
        spki.append(body)
        return spki
    }

    /// One DER TLV at the start of `bytes`: its tag, content, and total encoded length
    /// (tag + length octets + content). Definite lengths only; nil on any malformed
    /// or truncated encoding.
    private static func derTLV(_ bytes: [UInt8]) -> (tag: UInt8, content: [UInt8], totalLength: Int)? {
        guard bytes.count >= 2 else { return nil }
        let tag = bytes[0]
        let firstLengthByte = bytes[1]
        var contentStart = 2
        var length: Int
        if firstLengthByte < 0x80 {
            length = Int(firstLengthByte)
        } else {
            let lengthByteCount = Int(firstLengthByte & 0x7F)
            guard lengthByteCount > 0, lengthByteCount <= 4, bytes.count >= contentStart + lengthByteCount else {
                return nil
            }
            length = 0
            for index in 0 ..< lengthByteCount {
                length = (length << 8) | Int(bytes[contentStart + index])
            }
            contentStart += lengthByteCount
        }
        guard bytes.count >= contentStart + length else { return nil }
        return (tag, Array(bytes[contentStart ..< contentStart + length]), contentStart + length)
    }

    /// Reads a 4-byte big-endian length prefix from Apple's RSA external representation.
    private static func bigEndianUInt32(_ bytes: ArraySlice<UInt8>) -> Int {
        guard bytes.count == 4 else { return 0 }
        return bytes.reduce(Int(0)) { ($0 << 8) | Int($1) }
    }

    /// DER length octets: short form below 128, long form (0x80 | byte count) otherwise.
    private static func derLength(_ length: Int) -> Data {
        if length < 0x80 { return Data([UInt8(length)]) }
        var bytes: [UInt8] = []
        var value = length
        while value > 0 {
            bytes.insert(UInt8(value & 0xFF), at: 0)
            value >>= 8
        }
        return Data([UInt8(0x80 | bytes.count)]) + Data(bytes)
    }

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
