import Foundation

/// In-memory cache for an active verification session.
///
/// **Never persisted to Keychain or disk.** If the process is killed while a session is active,
/// the session is lost and a new one is initiated on next `verify()` call — this is correct
/// and expected behaviour.
///
/// The cache is used to restore state after the app returns to the foreground following a
/// background-during-biometric event (`LAError.appCancel`).
final class SessionCache {

    struct CachedSession {
        let sessionId: String
        let challenge: String
        let expiresAt: Date
        /// Number of consecutive expirations for this session chain. When this reaches 2,
        /// `VouchflowError.sessionExpiredRepeatedly` is thrown.
        let expiryCount: Int

        var isExpired: Bool {
            Date() >= expiresAt
        }
    }

    private var _session: CachedSession?
    private let lock = NSLock()

    func store(_ session: CachedSession) {
        lock.withLock { _session = session }
    }

    func current() -> CachedSession? {
        lock.withLock { _session }
    }

    func clear() {
        lock.withLock { _session = nil }
    }
}
