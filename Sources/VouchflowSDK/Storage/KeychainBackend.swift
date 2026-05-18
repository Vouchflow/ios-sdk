import Foundation

/// Storage abstraction for the SDK's persisted values — device token, pending-enrollment
/// placeholder, Secure Enclave key handle, and App Attest key id.
///
/// Mirrors the Android SDK's `TokenStore` interface. Two implementations exist:
///  - `KeychainManager` — OS Keychain; survives app reinstall.
///  - `InMemoryKeychainBackend` — process-lifetime fallback used when the Keychain is
///    structurally unavailable (missing entitlements / MDM restrictions) or disabled via
///    `VouchflowConfig.keychainStorage`.
///
/// `KeychainBackendFactory` selects the implementation at `configure()` time.
///
/// The protocol is throwing so a genuine, actionable Keychain failure can still surface to a
/// caller that needs to react (e.g. a transient device-locked error worth retrying). Callers
/// that treat persistence as an optional enhancement already swallow failures with `try?`.
protocol KeychainBackend: AnyObject {
    func read(key: String) throws -> String?
    func write(key: String, value: String) throws
    func delete(key: String) throws
    func exists(key: String) throws -> Bool
}

/// Process-lifetime, thread-safe in-memory `KeychainBackend`.
///
/// The fallback the SDK lands on when the Keychain cannot be used — because it is
/// structurally unavailable on the device/profile, or disabled via
/// `VouchflowConfig.keychainStorage`. Persistence is limited to the current process: the
/// device re-enrolls on next launch, and server-side reputation history is preserved
/// regardless. Never throws.
final class InMemoryKeychainBackend: KeychainBackend {

    private let lock = NSLock()
    private var store: [String: String] = [:]

    func read(key: String) -> String? {
        lock.lock(); defer { lock.unlock() }
        return store[key]
    }

    func write(key: String, value: String) {
        lock.lock(); defer { lock.unlock() }
        store[key] = value
    }

    func delete(key: String) {
        lock.lock(); defer { lock.unlock() }
        store.removeValue(forKey: key)
    }

    func exists(key: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return store[key] != nil
    }
}

#if targetEnvironment(simulator)
/// Simulator-only `KeychainBackend` backed by `UserDefaults`.
///
/// SPM `.testTarget` bundles loaded into the system `xctest` host on Simulator cannot carry
/// Keychain entitlements, so `SecItem*` calls return `errSecMissingEntitlement`. On Simulator
/// `KeychainManager` falls back to this backend. Unlike `InMemoryKeychainBackend` it persists
/// across `KeychainManager` instances within the test process — the reinstall-flow integration
/// test relies on that. Excluded entirely from real-device builds via `#if`.
final class UserDefaultsKeychainBackend: KeychainBackend {

    private let prefix = "vsk_fb_"
    private var defaults: UserDefaults { .standard }

    func read(key: String) -> String? { defaults.string(forKey: prefix + key) }
    func write(key: String, value: String) { defaults.set(value, forKey: prefix + key) }
    func delete(key: String) { defaults.removeObject(forKey: prefix + key) }
    func exists(key: String) -> Bool { defaults.string(forKey: prefix + key) != nil }
}
#endif
