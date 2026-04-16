import Foundation
import CryptoKit

/// Manages the ECDSA P-256 keypair stored in the Secure Enclave.
///
/// The private key never leaves the chip. `dataRepresentation` is an opaque handle that
/// allows the key to be reconstructed from the Secure Enclave on the same device — it is
/// not an export of the raw private key bytes.
///
/// The opaque handle is stored in Keychain under `KeychainKey.seKeyData` with
/// `kSecAttrAccessibleAfterFirstUnlock` so it survives reinstalls alongside the device token.
final class SecureEnclaveKeyManager {

    // MARK: - Key generation

    /// Generates a new keypair in the Secure Enclave.
    ///
    /// - Returns: The new private key and the public key as a base64 string in
    ///   SubjectPublicKeyInfo DER format. This matches Android's `PublicKey.encoded` and
    ///   is importable by Node.js as `{ format: 'der', type: 'spki' }`.
    func generateKeyPair() throws -> (
        privateKey: SecureEnclave.P256.Signing.PrivateKey,
        publicKeyBase64: String
    ) {
        let privateKey = try SecureEnclave.P256.Signing.PrivateKey()
        let publicKeyBase64 = privateKey.publicKey.derRepresentation.base64EncodedString()
        return (privateKey, publicKeyBase64)
    }

    // MARK: - Persistence

    /// Stores the key's opaque `dataRepresentation` in the Keychain.
    func storeKey(_ key: SecureEnclave.P256.Signing.PrivateKey, in keychain: KeychainManager) throws {
        try keychain.write(key: KeychainKey.seKeyData, value: key.dataRepresentation.base64EncodedString())
    }

    /// Loads the private key from the Keychain.
    ///
    /// Returns `nil` if no key has been stored (e.g. FRESH_ENROLLMENT or REINSTALL state).
    func loadKey(from keychain: KeychainManager) throws -> SecureEnclave.P256.Signing.PrivateKey? {
        guard let base64 = try keychain.read(key: KeychainKey.seKeyData),
              let data = Data(base64Encoded: base64) else {
            return nil
        }
        return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data)
    }

    /// Deletes the stored key handle from the Keychain.
    func deleteKey(from keychain: KeychainManager) throws {
        try keychain.delete(key: KeychainKey.seKeyData)
    }

    /// Whether a key handle exists in the Keychain (does not verify the key is still valid).
    func keyExists(in keychain: KeychainManager) throws -> Bool {
        try keychain.exists(key: KeychainKey.seKeyData)
    }
}
