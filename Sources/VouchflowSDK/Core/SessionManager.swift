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
    /// Uses `NotificationCenter.notifications(named:)` async sequence (iOS 15+).
    /// Returns immediately if the app is already in the foreground when called
    /// (the notification is only fired on transition, so this should only be called
    /// after confirming the app is backgrounded).
    func waitForForeground() async {
        for await _ in NotificationCenter.default
            .notifications(named: UIApplication.willEnterForegroundNotification)
            .prefix(1) {
            return
        }
    }
}
