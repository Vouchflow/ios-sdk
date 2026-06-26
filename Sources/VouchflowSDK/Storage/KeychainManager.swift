import Foundation
import Security

/// Keys used for Keychain items.
enum KeychainKey {
    /// The enrolled device token (`dvt_...`). Persists across app deletion with `AfterFirstUnlock`.
    static let deviceToken = "vs_device_token"
    /// Pending enrollment placeholder (`pending_dvt_<idempotencyKey>`). Cleared on successful enroll.
    static let pendingToken = "vs_pending_token"
    /// Opaque `dataRepresentation` of the Secure Enclave private key, base64-encoded.
    static let seKeyData = "vs_se_key_data"
    /// App Attest key identifier from `DCAppAttestService.generateKey()`.
    /// Persisted at enrollment so `signPayload` can produce fresh
    /// assertions for the `high` confidence path. ~32 char base64.
    static let appAttestKeyId = "vs_app_attest_key_id"
    /// "true"/"false" — whether the server attestation-verified the last
    /// enrollment. Drives one-time self-heal re-enroll for devices that
    /// enrolled while the server couldn't verify App Attest (server #8): the
    /// keychain survives reinstall, so without this they'd stay low forever.
    static let attestationVerified = "vs_attestation_verified"
}

/// Wraps Security framework Keychain operations. Conforms to `KeychainBackend`.
///
/// All items use `kSecAttrAccessibleAfterFirstUnlock` so the SDK can operate in the background
/// (e.g. during silent push handling) after the device has been unlocked at least once since
/// boot. This setting causes items to survive app deletion and reinstall — intentional for
/// device token persistence.
///
/// ## Self-healing fallback
/// If the Keychain is structurally unavailable — `errSecMissingEntitlement`, which happens for
/// SPM `.testTarget` bundles on Simulator and for some MDM-managed configurations — this
/// manager transparently switches to a fallback backend for the rest of its lifetime
/// (`InMemoryKeychainBackend` on device, `UserDefaultsKeychainBackend` on Simulator). The
/// device re-enrolls on next launch. This mirrors the Android SDK's AccountManager →
/// encrypted-storage fallback: a storage failure degrades gracefully, never fatal to the host.
///
/// Transient failures — `errSecInteractionNotAllowed`, i.e. the device is locked — are
/// surfaced as thrown errors so the caller can retry, rather than permanently demoting to the
/// fallback.
final class KeychainManager: KeychainBackend {
    private let service = "dev.vouchflow.sdk"
    private let accessGroup: String?

    /// Activated on the first `errSecMissingEntitlement`. Once set, every operation routes
    /// here. Guarded by `lock`.
    private var fallback: KeychainBackend?
    private let lock = NSLock()

    init(accessGroup: String? = nil) {
        self.accessGroup = accessGroup
    }

    // MARK: - Read

    func read(key: String) throws -> String? {
        if let fallback = activeFallback() {
            return try fallback.read(key: key)
        }

        var query = baseQuery(for: key)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            guard let data = result as? Data, let value = String(data: data, encoding: .utf8) else {
                throw KeychainError.unexpectedData
            }
            return value
        case errSecItemNotFound:
            return nil
        case errSecInteractionNotAllowed:
            throw KeychainError.accessDenied
        case errSecMissingEntitlement:
            return try activateFallback().read(key: key)
        default:
            throw KeychainError.operationFailed(status: status)
        }
    }

    // MARK: - Write

    func write(key: String, value: String) throws {
        if let fallback = activeFallback() {
            try fallback.write(key: key, value: value)
            return
        }

        let data = Data(value.utf8)
        var query = baseQuery(for: key)

        // Attempt update first; fall through to insert if the item doesn't exist.
        let updateStatus = SecItemUpdate(
            query as CFDictionary,
            [kSecValueData as String: data] as CFDictionary
        )

        switch updateStatus {
        case errSecSuccess:
            return
        case errSecItemNotFound:
            query[kSecValueData as String] = data
            query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
            let insertStatus = SecItemAdd(query as CFDictionary, nil)
            switch insertStatus {
            case errSecSuccess:
                return
            case errSecMissingEntitlement:
                try activateFallback().write(key: key, value: value)
            default:
                throw KeychainError.operationFailed(status: insertStatus)
            }
        case errSecMissingEntitlement:
            try activateFallback().write(key: key, value: value)
        default:
            throw KeychainError.operationFailed(status: updateStatus)
        }
    }

    // MARK: - Delete

    func delete(key: String) throws {
        if let fallback = activeFallback() {
            try fallback.delete(key: key)
            return
        }

        let query = baseQuery(for: key)
        let status = SecItemDelete(query as CFDictionary)

        switch status {
        case errSecSuccess, errSecItemNotFound:
            return
        case errSecMissingEntitlement:
            try activateFallback().delete(key: key)
        default:
            throw KeychainError.operationFailed(status: status)
        }
    }

    // MARK: - Existence check

    func exists(key: String) throws -> Bool {
        try read(key: key) != nil
    }

    // MARK: - Private

    /// Returns the fallback backend if it has been activated, else `nil`.
    private func activeFallback() -> KeychainBackend? {
        lock.lock(); defer { lock.unlock() }
        return fallback
    }

    /// Activates (once) and returns the fallback backend. Idempotent and thread-safe.
    @discardableResult
    private func activateFallback() -> KeychainBackend {
        lock.lock(); defer { lock.unlock() }
        if let existing = fallback {
            return existing
        }
        VouchflowLogger.warn(
            "[VouchflowSDK] Keychain unavailable (errSecMissingEntitlement) — using fallback "
                + "storage. Token persistence may not survive an app reinstall."
        )
        #if targetEnvironment(simulator)
        let created: KeychainBackend = UserDefaultsKeychainBackend()
        #else
        let created: KeychainBackend = InMemoryKeychainBackend()
        #endif
        fallback = created
        return created
    }

    private func baseQuery(for key: String) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]
        if let group = accessGroup {
            query[kSecAttrAccessGroup as String] = group
        }
        return query
    }
}

// MARK: - Errors

enum KeychainError: Error {
    case accessDenied
    case unexpectedData
    case operationFailed(status: OSStatus)
}

// Converting KeychainError to VouchflowError at the call site keeps the internals clean.
extension KeychainError {
    var asVouchflowError: VouchflowError {
        switch self {
        case .accessDenied:
            return .keychainAccessDenied
        case .unexpectedData, .operationFailed:
            return .enrollmentFailed(underlying: self)
        }
    }
}
