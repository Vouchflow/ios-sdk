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
}

/// Wraps Security framework Keychain operations.
///
/// All items use `kSecAttrAccessibleAfterFirstUnlock` so the SDK can operate in the background
/// (e.g. during silent push handling) after the device has been unlocked at least once since boot.
/// This setting causes items to survive app deletion and reinstall — intentional for device
/// token persistence.
final class KeychainManager {
    private let service = "dev.vouchflow.sdk"
    private let accessGroup: String?

    /// CI-only fallback: SPM .testTarget bundles loaded into xctest on Simulator
    /// can't be granted Keychain entitlements, so all SecItem* calls return -34018.
    /// When `VOUCHFLOW_TEST_KEYCHAIN_FALLBACK=1` is set in the process environment
    /// (only ever by our own xcodebuild test invocation), persistence is routed
    /// through UserDefaults instead. SDK consumers and production builds never
    /// set this env var, so they always use the real Keychain.
    private let useFallback: Bool = ProcessInfo.processInfo.environment["VOUCHFLOW_TEST_KEYCHAIN_FALLBACK"] == "1"
    private let fallbackPrefix = "vsk_fb_"

    init(accessGroup: String? = nil) {
        self.accessGroup = accessGroup
    }

    // MARK: - Read

    func read(key: String) throws -> String? {
        if useFallback {
            return UserDefaults.standard.string(forKey: fallbackPrefix + key)
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
        default:
            throw KeychainError.operationFailed(status: status)
        }
    }

    // MARK: - Write

    func write(key: String, value: String) throws {
        if useFallback {
            UserDefaults.standard.set(value, forKey: fallbackPrefix + key)
            return
        }

        let data = Data(value.utf8)
        var query = baseQuery(for: key)

        // Attempt update first; fall through to insert if item doesn't exist.
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
            guard insertStatus == errSecSuccess else {
                throw KeychainError.operationFailed(status: insertStatus)
            }
        default:
            throw KeychainError.operationFailed(status: updateStatus)
        }
    }

    // MARK: - Delete

    func delete(key: String) throws {
        if useFallback {
            UserDefaults.standard.removeObject(forKey: fallbackPrefix + key)
            return
        }

        let query = baseQuery(for: key)
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.operationFailed(status: status)
        }
    }

    // MARK: - Existence check

    func exists(key: String) throws -> Bool {
        try read(key: key) != nil
    }

    // MARK: - Private

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
