import Foundation

/// Result of the standard X.509 chain evaluation that must precede pin comparison.
enum TrustEvaluation: Equatable {
    /// The chain validated against the OS trust store for the expected hostname.
    case passed

    /// Chain validation failed — expiry, revoked or untrusted root, malformed chain, or
    /// hostname mismatch. `reason` is the OS-supplied description, surfaced verbatim to
    /// the developer so a stale-clock failure reads differently from a real MITM.
    case failed(reason: String)
}

/// Why a server-trust challenge was rejected.
enum PinningRejection: Equatable {
    /// `SecTrustEvaluateWithError` failed against an SSL policy bound to the expected host.
    /// The connection never reached pin comparison — the chain is not trustworthy at all.
    case trustEvaluationFailed(reason: String)

    /// The chain is genuinely valid for the expected host, but no certificate in it carried
    /// a SubjectPublicKeyInfo matching a configured pin. `served` is every SPKI hash the
    /// chain presented, so the developer can diff configured vs. served.
    case pinMismatch(served: [String])

    /// Placeholder (`TODO-…`) pins in a release build. A configuration error: nothing the
    /// server can present will fix it.
    case placeholderPinsInReleaseBuild

    /// The SDK could not derive the hostname to validate against from its configuration.
    /// Fail closed rather than evaluate against an unbound policy.
    case missingExpectedHost
}

/// What the delegate should do with a server-trust challenge.
enum PinningDecision: Equatable {
    case accept

    /// Debug builds only: the chain passed full trust evaluation, and pin comparison was
    /// deliberately skipped because the config still holds placeholder pins.
    case acceptPlaceholderPinsInDebugBuild

    case reject(PinningRejection)
}

/// The pinning decision expressed as a pure function of its inputs.
///
/// Pinning is an **additional** constraint layered on top of standard TLS validation, never
/// a substitute for it. Before v2.5.0 this SDK accepted a connection the moment any
/// certificate in the presented chain matched a configured pin — no `SecTrustEvaluateWithError`,
/// no `SecPolicyCreateSSL`, so expiry, revocation, untrusted roots and hostname were all
/// unchecked. With a *leaf* pin that was masked by the fact that exactly one key could pass.
/// With an *intermediate* pin (e.g. Let's Encrypt YE1/YE2, which appears in the chain of every
/// certificate that CA issues) it would have accepted any attacker holding any certificate
/// from that CA for any domain. Hence: evaluate first, pin second.
///
/// Kept free of `Security` types so the ordering guarantee above is exhaustively unit-testable;
/// `PinningDelegate` is the thin adapter that supplies the real `SecTrust` results.
enum PinningPolicy {

    /// - Parameters:
    ///   - trustEvaluation: Outcome of `SecTrustEvaluateWithError` against an SSL policy
    ///     bound to the expected hostname.
    ///   - servedSpkiSha256: Base64 SHA-256 SPKI hash of each certificate the server presented.
    ///   - configuredPins: Pins from `VouchflowConfig` (leaf and intermediate). OR semantics —
    ///     any one matching is sufficient, which is what allows zero-downtime leaf rotation.
    ///   - pinsArePlaceholders: `VouchflowConfig.hasTodoPlaceholderPins`.
    ///   - allowPlaceholderPinBypass: `true` in debug builds only. Bypasses **pin comparison
    ///     only** — trust evaluation still has to pass.
    static func decide(
        trustEvaluation: TrustEvaluation,
        servedSpkiSha256: [String],
        configuredPins: [String],
        pinsArePlaceholders: Bool,
        allowPlaceholderPinBypass: Bool
    ) -> PinningDecision {
        // Checked first because it is a build-configuration error, not a verdict on the
        // server: reporting "placeholder pins in a release build" is more actionable than
        // whatever the chain happens to look like.
        if pinsArePlaceholders && !allowPlaceholderPinBypass {
            return .reject(.placeholderPinsInReleaseBuild)
        }

        // Standard validation must pass on its own merits, unconditionally — including on
        // the debug placeholder-pin path below, which skips pins but never this.
        if case .failed(let reason) = trustEvaluation {
            return .reject(.trustEvaluationFailed(reason: reason))
        }

        if pinsArePlaceholders {
            return .acceptPlaceholderPinsInDebugBuild
        }

        // Empty/blank pins must never match a chain that presented no hashes either.
        let configured = Set(configuredPins.filter { !$0.isEmpty })
        if servedSpkiSha256.contains(where: { configured.contains($0) }) {
            return .accept
        }
        return .reject(.pinMismatch(served: servedSpkiSha256))
    }
}
