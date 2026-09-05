import Foundation
import Security

/// Certificate fixtures for `PinningDelegateTrustTests`.
///
/// All five certificates were generated once, offline, with OpenSSL and are checked in as
/// base64 DER. They are throwaway EC P-256 test certificates for a CA that exists nowhere
/// but this file — no private key is committed, and none of them is trusted by any real
/// device.
///
/// Every leaf's validity is under 398 days, and every test pins evaluation to a fixed
/// `verifyDate` inside those windows, so these tests do not start failing on a future date.
/// Regenerating them requires re-deriving each `…SPKI` constant alongside the DER.
enum PinningTestCertificates {

    /// Fixed evaluation instant: 2026-10-01T00:00:00Z. Inside the validity window of every
    /// fixture except `expiredLeafDER`, which is the point of that one.
    static let verifyDate = Date(timeIntervalSince1970: 1_790_812_800)

    /// Self-signed test root CA (EC P-256), valid 2026-09-05 → 2046-08-31.
    ///
    /// Stands in for a publicly trusted CA — Let's Encrypt YE1/YE2 in the real
    /// deployment — that the SDK pins at the *intermediate* level.
    static let caDER = """
        MIIBsDCCAVWgAwIBAgIUBs883ndXpkol3+61BfbYEgFmq4QwCgYIKoZIzj0EAwIwJTEjMCEGA1UE
        AwwaVm91Y2hmbG93IFNESyBUZXN0IFJvb3QgQ0EwHhcNMjYwOTA1MDAxMzU0WhcNNDYwODMxMDAx
        MzU0WjAlMSMwIQYDVQQDDBpWb3VjaGZsb3cgU0RLIFRlc3QgUm9vdCBDQTBZMBMGByqGSM49AgEG
        CCqGSM49AwEHA0IABFC375/riE/1GwIt433EbvVGuj510yragdaSqvLHDTMbBBrvDjm65/NWK3D0
        iS2xVUl62hc19gz4d/FbhCZanN6jYzBhMB0GA1UdDgQWBBRaYeePqmP8Zd8FO5Ekb19fpmxUDDAf
        BgNVHSMEGDAWgBRaYeePqmP8Zd8FO5Ekb19fpmxUDDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB
        /wQEAwIBBjAKBggqhkjOPQQDAgNJADBGAiEAkH+7bcr0PjQO+2ZSkMtDyRnoiROP8QvYqMp0zkZR
        4wUCIQCBQ13FUn3sg+n5nFz3PaPVuuZ7E6W4TWLjcKgmf2GJ2A==
        """

    /// Base64 SHA-256 of `caDER`'s SubjectPublicKeyInfo — the value a pin holds.
    static let caSPKI = "rNAtbPL0BoBaByIGNLtHpUwe01gJ7aMaS73uM3Obq8M="

    /// Leaf for `api.vouchflow.dev` issued by `caDER`, valid 2026-09-05 → 2027-09-01.
    /// The honest server.
    static let validLeafDER = """
        MIIB2DCCAX6gAwIBAgIUKs5aspFZWJdnhuZsRTVwJ/dO79swCgYIKoZIzj0EAwIwJTEjMCEGA1UE
        AwwaVm91Y2hmbG93IFNESyBUZXN0IFJvb3QgQ0EwHhcNMjYwOTA1MDAxMzU0WhcNMjcwOTAxMDAw
        MDAwWjAcMRowGAYDVQQDDBFhcGkudm91Y2hmbG93LmRldjBZMBMGByqGSM49AgEGCCqGSM49AwEH
        A0IABOYzkB/LCQ/oGvoIdr4KzGkr6Eam8tNvGDSKukSuuG7yDSepY+l1gNH1C0955K4578w9PpeL
        wiSPOWDbOVJejRujgZQwgZEwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAww
        CgYIKwYBBQUHAwEwHAYDVR0RBBUwE4IRYXBpLnZvdWNoZmxvdy5kZXYwHQYDVR0OBBYEFBmebjOt
        j574KCZ1zW9hnXu3zvLMMB8GA1UdIwQYMBaAFFph54+qY/xl3wU7kSRvX1+mbFQMMAoGCCqGSM49
        BAMCA0gAMEUCIQCdr39kqMwXxHGJQXmALJ0DwiFmmopi8RXYqKPGSaBWCwIgHjw5nurQEUsuE+Ge
        uTFDG9yWQLP7jnJ0TWBJKd681Sg=
        """

    /// Base64 SHA-256 of `validLeafDER`'s SubjectPublicKeyInfo — the value a pin holds.
    static let validLeafSPKI = "qw+ULJRgX7Vs2xS5Qqh+2ye3wCxuB5c/nd3Joe9Nq54="

    /// Leaf for `attacker.example.com` issued by the SAME `caDER`, same validity
    /// window as `validLeafDER`.
    ///
    /// This is the attacker in the intermediate-pinning scenario: a genuine,
    /// free, minutes-to-obtain certificate from the pinned CA, for a domain they
    /// legitimately control. Its chain contains `caDER`, so it satisfies an
    /// intermediate pin. Only hostname validation stops it.
    static let attackerLeafDER = """
        MIIB3jCCAYOgAwIBAgITb9OGxAfNUnt8Ifr5GRacOpIEnTAKBggqhkjOPQQDAjAlMSMwIQYDVQQD
        DBpWb3VjaGZsb3cgU0RLIFRlc3QgUm9vdCBDQTAeFw0yNjA5MDUwMDEzNTRaFw0yNzA5MDEwMDAw
        MDBaMB8xHTAbBgNVBAMMFGF0dGFja2VyLmV4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0D
        AQcDQgAEEAFiTVzYYU1sJwiR0O2qB0DZz/S7xFtIY+LnJeM21Y3YJsxOBdktx/AVzQGEhWhPNkEs
        0l27dn2GNCAEgKkcbKOBlzCBlDAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUE
        DDAKBggrBgEFBQcDATAfBgNVHREEGDAWghRhdHRhY2tlci5leGFtcGxlLmNvbTAdBgNVHQ4EFgQU
        bqIXcLLraZQKMrh/1lxF8NHAIBQwHwYDVR0jBBgwFoAUWmHnj6pj/GXfBTuRJG9fX6ZsVAwwCgYI
        KoZIzj0EAwIDSQAwRgIhAMpBz1Cpi7+C3vvd7TaHxrVveaYC7LDqz7ZdpYZl/PFWAiEAj4m916pR
        1lbyZz0aq5bn+4/P0DEBKxxrBIBOLba2bYQ=
        """

    /// Base64 SHA-256 of `attackerLeafDER`'s SubjectPublicKeyInfo — the value a pin holds.
    static let attackerLeafSPKI = "14xu+iyyGiYSPJ+T+wLhgVAU47B/tMrtJsNgi2vKLjY="

    /// Leaf for `api.vouchflow.dev` issued by `caDER`, valid 2020-01-01 →
    /// 2021-01-01 — long expired at `verifyDate`.
    static let expiredLeafDER = """
        MIIB2DCCAX6gAwIBAgIUMPMzmfFhXrfZYsaj8BsdEe51YswwCgYIKoZIzj0EAwIwJTEjMCEGA1UE
        AwwaVm91Y2hmbG93IFNESyBUZXN0IFJvb3QgQ0EwHhcNMjAwMTAxMDAwMDAwWhcNMjEwMTAxMDAw
        MDAwWjAcMRowGAYDVQQDDBFhcGkudm91Y2hmbG93LmRldjBZMBMGByqGSM49AgEGCCqGSM49AwEH
        A0IABBrIpPOu+P2ja/EkLUHKHoRp8vODyUg7mHqoJyY74q8ItGusl/z09tBcJ9Yzsb8b/6HhJojD
        rVHrXFxtTM/vBXSjgZQwgZEwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAww
        CgYIKwYBBQUHAwEwHAYDVR0RBBUwE4IRYXBpLnZvdWNoZmxvdy5kZXYwHQYDVR0OBBYEFKSFcjqP
        v08YMaTGwbZZr9CsOXorMB8GA1UdIwQYMBaAFFph54+qY/xl3wU7kSRvX1+mbFQMMAoGCCqGSM49
        BAMCA0gAMEUCIBF00RwXZlhG3s5w1mSgCresgLeKkuZPiI5eYjlJaFxFAiEA7U9wnibj5MB2AxFf
        ZnukROo5N8oSlCzPwIJyX905NAQ=
        """

    /// Base64 SHA-256 of `expiredLeafDER`'s SubjectPublicKeyInfo — the value a pin holds.
    static let expiredLeafSPKI = "WG1G5cYNxBtsHJB9q5ou8adwVthxQrHNm+dTn7pMNV8="

    /// Self-signed leaf for `api.vouchflow.dev`, valid 2026-09-05 → 2027-08-31.
    /// Correct hostname, in date, chains to nothing trusted.
    static let selfSignedLeafDER = """
        MIIBzzCCAXWgAwIBAgIUTMeemfCmBGWcaRem4J2JIl9kRL4wCgYIKoZIzj0EAwIwHDEaMBgGA1UE
        AwwRYXBpLnZvdWNoZmxvdy5kZXYwHhcNMjYwOTA1MDAxNzQ0WhcNMjcwODMxMDAxNzQ0WjAcMRow
        GAYDVQQDDBFhcGkudm91Y2hmbG93LmRldjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMV+PLj6
        9JVr99FM8DRLwdqjRZai3GPcm3kLoBQRFDSG5xKyV4h4yYAaZR27BRU6HD3FtckejlHHArO3oikl
        qLajgZQwgZEwHQYDVR0OBBYEFPF6oFPTG1hFPlrIKJUguCaVgNz2MB8GA1UdIwQYMBaAFPF6oFPT
        G1hFPlrIKJUguCaVgNz2MAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoG
        CCsGAQUFBwMBMBwGA1UdEQQVMBOCEWFwaS52b3VjaGZsb3cuZGV2MAoGCCqGSM49BAMCA0gAMEUC
        IFAXSCchs+CYdSUeUM6l+ppD27Rj+dDEaKt4U43oVkzYAiEA8MpMvOG9b0kImqqcbzqKK098taOj
        /ecTq+OOZgz/Lrs=
        """

    /// Base64 SHA-256 of `selfSignedLeafDER`'s SubjectPublicKeyInfo — the value a pin holds.
    static let selfSignedLeafSPKI = "3rRZq54V4LnnPJmhBfM+KoUUS+td4Jifp88lphn6Io4="

    // MARK: - Loading

    /// Decodes one of the base64 DER constants above into a `SecCertificate`.
    /// Returns `nil` only if a fixture has been corrupted in-tree.
    static func certificate(fromBase64DER base64: String) -> SecCertificate? {
        guard let der = Data(base64Encoded: base64, options: [.ignoreUnknownCharacters]) else {
            return nil
        }
        return SecCertificateCreateWithData(nil, der as CFData)
    }
}
