import Foundation
import os.log

/// Internal SDK logger. Uses `os.log` so output appears in Console.app and Xcode console.
/// Not exposed to the developer — this is for SDK diagnostics only.
enum VouchflowLogger {
    private static let logger = Logger(subsystem: "dev.vouchflow.sdk", category: "VouchflowSDK")

    static func debug(_ message: String) {
        logger.debug("\(message, privacy: .public)")
    }

    static func warn(_ message: String) {
        logger.warning("\(message, privacy: .public)")
    }

    static func error(_ message: String) {
        logger.error("\(message, privacy: .public)")
    }
}
