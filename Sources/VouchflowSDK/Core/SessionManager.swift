import Foundation
import UIKit

/// Provides app lifecycle signals to the verification flow.
///
/// When the OS sends the app to the background mid-biometric, `LAContext` cancels the
/// biometric prompt with `LAError.appCancel`. `VerificationManager` catches this and calls
/// `waitForForeground()` to pause until the user returns to the app, at which point the
/// biometric prompt is silently re-presented.
final class SessionManager {

    static let shared = SessionManager()
    private init() {}

    /// Suspends until the app next enters the foreground.
    ///
    /// Runs on the main actor because `NotificationCenter.default` and `UIApplication`
    /// notifications are main-actor-isolated in Swift 5.10+.
    @MainActor
    func waitForForeground() async {
        for await _ in NotificationCenter.default
            .notifications(named: UIApplication.willEnterForegroundNotification)
            .prefix(1) {
            return
        }
    }
}
