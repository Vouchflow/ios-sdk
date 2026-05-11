import Foundation
import XCTest
@testable import VouchflowSDK

/// JCS output must be byte-identical across iOS / Android / Web. If this
/// SDK's canonicalization drifts, the SHA-256 server-side payload check
/// won't match what the SDK signed, and signed-payload verification
/// silently breaks.
final class JCSCanonicalizerTests: XCTestCase {

    // MARK: Primitives

    func test_null() {
        XCTAssertEqual(JCSCanonicalizer.canonicalize(NSNull()), "null")
    }

    func test_booleans() {
        // Cast to Any to dispatch to the non-throwing Any-overload — without
        // the cast, Swift prefers the generic `Encodable` overload (which
        // throws) and the test calls would require `try`.
        XCTAssertEqual(JCSCanonicalizer.canonicalize(true as Any), "true")
        XCTAssertEqual(JCSCanonicalizer.canonicalize(false as Any), "false")
    }

    func test_integers() {
        XCTAssertEqual(JCSCanonicalizer.canonicalize(0 as Any), "0")
        XCTAssertEqual(JCSCanonicalizer.canonicalize(123 as Any), "123")
        XCTAssertEqual(JCSCanonicalizer.canonicalize(-7 as Any), "-7")
    }

    func test_strings() {
        XCTAssertEqual(JCSCanonicalizer.canonicalize("hello" as Any), "\"hello\"")
        XCTAssertEqual(JCSCanonicalizer.canonicalize("a\"b" as Any), "\"a\\\"b\"")
        XCTAssertEqual(JCSCanonicalizer.canonicalize("a\nb" as Any), "\"a\\nb\"")
    }

    // MARK: Collections

    func test_emptyCollections() {
        XCTAssertEqual(JCSCanonicalizer.canonicalize([Any]()), "[]")
        XCTAssertEqual(JCSCanonicalizer.canonicalize([String: Any]()), "{}")
    }

    func test_arrayPreservesOrder() {
        XCTAssertEqual(JCSCanonicalizer.canonicalize([3, 1, 2] as Any), "[3,1,2]")
    }

    func test_objectKeysAreSorted() {
        let obj: [String: Any] = ["b": 1, "a": 2, "c": 3]
        XCTAssertEqual(JCSCanonicalizer.canonicalize(obj), "{\"a\":2,\"b\":1,\"c\":3}")
    }

    func test_nestedObjectSorted() {
        let obj: [String: Any] = ["z": ["b": 1, "a": 2], "a": 1]
        XCTAssertEqual(
            JCSCanonicalizer.canonicalize(obj),
            "{\"a\":1,\"z\":{\"a\":2,\"b\":1}}"
        )
    }

    // MARK: Cross-platform invariant — must match the TypeScript port byte-for-byte

    func test_mandateShapedPayload_matchesTypeScriptOutput() {
        let payload: [String: Any] = [
            "v": 1,
            "id": "mand_abc",
            "grants": [
                ["asset": "usd", "max": 500],
                ["asset": "eth", "max": 0.5],
            ],
            "expires_at": "2026-12-31T00:00:00Z",
        ]
        // The TypeScript canonicalize() produces this exact string for the
        // same input. See web-sdk/test/unit/canonicalize.test.ts.
        let expected = #"{"expires_at":"2026-12-31T00:00:00Z","grants":[{"asset":"usd","max":500},{"asset":"eth","max":0.5}],"id":"mand_abc","v":1}"#
        XCTAssertEqual(JCSCanonicalizer.canonicalize(payload), expected)
    }

    func test_idempotent() throws {
        let obj: [String: Any] = [
            "z": [3, 1, 2],
            "a": ["y": false, "x": NSNull()] as [String: Any],
        ]
        let out = JCSCanonicalizer.canonicalize(obj)
        let reparsed = try JSONSerialization.jsonObject(
            with: out.data(using: .utf8)!
        )
        XCTAssertEqual(JCSCanonicalizer.canonicalize(reparsed), out)
    }

    // MARK: Encodable round-trip

    struct Mandate: Encodable {
        let v: Int
        let id: String
        let scope: String
    }

    func test_encodableRoundtrip() throws {
        let m = Mandate(v: 1, id: "mand_abc", scope: "send")
        let out = try JCSCanonicalizer.canonicalize(m)
        XCTAssertEqual(out, #"{"id":"mand_abc","scope":"send","v":1}"#)
    }

    func test_differentOrderingsProduceIdenticalOutput() {
        let a: [String: Any] = ["name": "mandate", "amount": 100, "scope": "send"]
        let b: [String: Any] = ["scope": "send", "amount": 100, "name": "mandate"]
        XCTAssertEqual(
            JCSCanonicalizer.canonicalize(a),
            JCSCanonicalizer.canonicalize(b)
        )
    }
}
