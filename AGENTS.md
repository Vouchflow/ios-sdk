# Project agent memory

This file is the project's committed home for project-intrinsic agent knowledge: build, test, release, architecture, and sharp-edge notes that should travel with the code.

- Add durable project-specific notes here as they are discovered through real work.

## Build & test

There is no Swift toolchain on the Linux dev host — nothing here compiles locally. CI
(`.github/workflows/ios.yml`, macOS runner, Xcode 15.4) is the only place the package builds,
so treat a green CI run as the first real compile check. SwiftLint lints `Sources/` only
(`.swiftlint.yml`); `try!`, `as!`, `fatalError(` and `force_try`/`force_cast` are hard errors
there because an SDK must never crash its host app.

## Releasing

Tag-driven, not push-driven. `VERSION` must equal the tag being pushed or the release job
fails its own sanity check — bump `VERSION` in the PR, then push `vX.Y.Z` after merge.
Adding a `VouchflowError` case is a minor bump (see `git log` for 2.3.0 / 2.5.0).

## Certificate pinning: validate first, then pin

`PinningDelegate` must run `SecTrustEvaluateWithError` against an SSL policy bound to the
configured host *before* comparing SPKI pins, and a pin match must never substitute for that.
The ordering is the whole point: the pins sit on the Let's Encrypt intermediate, which appears
in the chain of every certificate that CA issues, so pin-only acceptance would admit anyone
holding any LE certificate for any domain. The rule lives as a pure function in
`Sources/VouchflowSDK/Network/PinningPolicy.swift`; the delegate is a thin adapter over it.
Do not reorder, and do not let the DEBUG placeholder-pin path skip trust evaluation.
`Tests/VouchflowSDKTests/PinningDelegateTrustTests.swift` proves it with real `SecTrust`
objects; regenerating those fixtures means re-deriving each `…SPKI` constant from its own DER.

## SPKI hashing: EC headers, RSA assembly

`PinningDelegate` supports EC P-256/P-384 (fixed SPKI header + raw point) and RSA
2048/3072/4096. RSA cannot reuse the header trick: Apple's RSA
`SecKeyCopyExternalRepresentation` is `[4-byte BE length][modulus][4-byte BE length][exponent]`,
not DER, so `rsaSPKI` strips the prefixes and re-wraps the INTEGERs with lengths computed
from the actual bytes. The RSA roots Speakeasy pins are ISRG Root X1 (RSA 4096) and X2
(EC P-384); their expected hashes and DER fixtures live in
`Tests/VouchflowSDKTests/PinningRealRootCertificates.swift`, and every pin constant there
is derived — never hand-written — with
`openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64`,
then cross-checked by the test target's independent ASN.1 walk (`IndependentSPKI`).

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
