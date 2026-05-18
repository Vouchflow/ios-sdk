# SDK Parity

The Android and iOS Vouchflow SDKs implement **one shared product contract**. The canonical
parity spec — the shared version policy, the public API surface and storage contract that
must match, accepted platform divergences, and the parity process — lives in the
`android-sdk` repository:

**https://github.com/Vouchflow/android-sdk/blob/main/SDK_PARITY_SPEC.md**

Any change to this SDK's public API surface or storage behaviour is parity-relevant: label
the PR `parity:needed` and follow §6 of the spec. When such a PR merges, the parity-mirror
workflow opens a tracking issue in `android-sdk`.
