import XCTest
@testable import VouchflowSDK

/// Unit tests for the `KeychainBackend` storage abstraction — the iOS counterpart of the
/// Android SDK's `TokenStore`. Mirrors `DeferredTokenStoreTest` on Android.
final class KeychainBackendTests: XCTestCase {

    // MARK: - InMemoryKeychainBackend

    func test_inMemory_roundTripsDeviceToken() {
        let backend = InMemoryKeychainBackend()

        XCTAssertNil(backend.read(key: KeychainKey.deviceToken))
        XCTAssertFalse(backend.exists(key: KeychainKey.deviceToken))

        backend.write(key: KeychainKey.deviceToken, value: "dvt_inmemory_test")
        XCTAssertEqual(backend.read(key: KeychainKey.deviceToken), "dvt_inmemory_test")
        XCTAssertTrue(backend.exists(key: KeychainKey.deviceToken))

        backend.delete(key: KeychainKey.deviceToken)
        XCTAssertNil(backend.read(key: KeychainKey.deviceToken))
        XCTAssertFalse(backend.exists(key: KeychainKey.deviceToken))
    }

    func test_inMemory_keysAreIndependent() {
        let backend = InMemoryKeychainBackend()
        backend.write(key: KeychainKey.deviceToken, value: "dvt")
        backend.write(key: KeychainKey.pendingToken, value: "pending")

        XCTAssertEqual(backend.read(key: KeychainKey.deviceToken), "dvt")
        XCTAssertEqual(backend.read(key: KeychainKey.pendingToken), "pending")

        backend.delete(key: KeychainKey.deviceToken)
        XCTAssertNil(backend.read(key: KeychainKey.deviceToken))
        XCTAssertEqual(backend.read(key: KeychainKey.pendingToken), "pending")
    }

    // MARK: - KeychainBackendFactory

    func test_factory_keychainStorageEnabled_returnsKeychainManager() {
        let backend = KeychainBackendFactory.make(config: VouchflowConfig(apiKey: "vsk_test"))
        XCTAssertTrue(backend is KeychainManager)
    }

    func test_factory_keychainStorageDisabled_returnsInMemoryBackend() {
        let backend = KeychainBackendFactory.make(
            config: VouchflowConfig(apiKey: "vsk_test", keychainStorage: false)
        )
        XCTAssertTrue(backend is InMemoryKeychainBackend)
    }

    // MARK: - Fault injection

    /// The `KeychainBackend` protocol makes the storage layer fault-injectable: a test double
    /// that always fails proves failure paths can be exercised in unit tests — the capability
    /// the iOS SDK previously lacked because managers depended on the concrete `KeychainManager`.
    func test_failingBackend_conformsAndThrows() {
        let backend: KeychainBackend = FailingKeychainBackend()
        XCTAssertThrowsError(try backend.read(key: KeychainKey.deviceToken))
        XCTAssertThrowsError(try backend.write(key: KeychainKey.deviceToken, value: "x"))
        XCTAssertThrowsError(try backend.delete(key: KeychainKey.deviceToken))
        XCTAssertThrowsError(try backend.exists(key: KeychainKey.deviceToken))
    }
}

/// Fault-injection double: every operation throws.
private final class FailingKeychainBackend: KeychainBackend {
    struct Failure: Error {}
    func read(key: String) throws -> String? { throw Failure() }
    func write(key: String, value: String) throws { throw Failure() }
    func delete(key: String) throws { throw Failure() }
    func exists(key: String) throws -> Bool { throw Failure() }
}
