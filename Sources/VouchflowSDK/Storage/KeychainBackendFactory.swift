import Foundation

/// Selects the `KeychainBackend` implementation for the current configuration.
///
///  - `KeychainManager` when `VouchflowConfig.keychainStorage` is `true` (the default) —
///    OS Keychain, survives reinstall.
///  - `InMemoryKeychainBackend` when `keychainStorage` is `false` — for environments that
///    restrict or forbid Keychain use. Token persistence is then process-lifetime only.
///
/// Note: even with `keychainStorage == true`, `KeychainManager` itself self-heals to an
/// in-memory backend if the Keychain turns out to be structurally unavailable at runtime —
/// so storage failure always degrades gracefully, it is never fatal.
enum KeychainBackendFactory {

    static func make(config: VouchflowConfig) -> KeychainBackend {
        guard config.keychainStorage else {
            VouchflowLogger.debug(
                "[VouchflowSDK] Storage: in-memory (Keychain disabled via VouchflowConfig)."
            )
            return InMemoryKeychainBackend()
        }
        return KeychainManager(accessGroup: config.keychainAccessGroup)
    }
}
