import Foundation

/// Certificate fixtures for `PinningRSATests`: the two real Let's Encrypt roots Speakeasy
/// pins, plus a throwaway generated RSA PKI covering the remaining standard RSA sizes.
///
/// The ISRG roots are the genuine publicly trusted certificates (checked in as base64 DER,
/// same convention as `PinningTestCertificates`). The RSA test roots and leaf were generated
/// once, offline, with OpenSSL (a throwaway CA that exists nowhere but this file — no real
/// trust, leaf validity under 398 days, evaluated at the fixed `verifyDate` of
/// `PinningTestCertificates`, inside every fixture's validity window).
///
/// Every `…SPKI` constant below is NOT hand-written: it was derived with the openssl
/// pipeline the SDK's hash must reproduce byte-for-byte,
///
///     openssl x509 -in CERT -pubkey -noout | openssl pkey -pubin -outform der |
///         openssl dgst -sha256 -binary | base64
///
/// and each test additionally re-derives the expected hash in-process with an independent
/// ASN.1 walk (`IndependentSPKI`), so a mistyped constant and an SDK bug cannot cancel out.
enum PinningRealRootCertificates {

    // MARK: - Real Let's Encrypt roots (Speakeasy's two configured pin slots)

    /// ISRG Root X1 — RSA 4096, the slot that was inert before the RSA fix: `spkiHeader`
    /// returned nil for RSA keys, so this certificate was silently skipped in the pin loop.
    static let isrgRootX1DER = """
        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
        """

    /// Base64 SHA-256 of `isrgRootX1DER`'s SubjectPublicKeyInfo, derived with the openssl
    /// pipeline documented on the enum.
    static let isrgRootX1SPKI = "C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M="

    /// ISRG Root X2 — EC P-384, Speakeasy's other slot. Guards the P-384 branch against
    /// real-certificate bytes (the older fixtures are all P-256).
    static let isrgRootX2DER = """
        MIICGzCCAaGgAwIBAgIQQdKd0XLq7qeAwSxs6S+HUjAKBggqhkjOPQQDAzBPMQsw
        CQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2gg
        R3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMjAeFw0yMDA5MDQwMDAwMDBaFw00
        MDA5MTcxNjAwMDBaME8xCzAJBgNVBAYTAlVTMSkwJwYDVQQKEyBJbnRlcm5ldCBT
        ZWN1cml0eSBSZXNlYXJjaCBHcm91cDEVMBMGA1UEAxMMSVNSRyBSb290IFgyMHYw
        EAYHKoZIzj0CAQYFK4EEACIDYgAEzZvVn4CDCuwJSvMWSj5cz3es3mcFDR0HttwW
        +1qLFNvicWDEukWVEYmO6gbf9yoWHKS5xcUy4APgHoIYOIvXRdgKam7mAHf7AlF9
        ItgKbppbd9/w+kHsOdx1ymgHDB/qo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0T
        AQH/BAUwAwEB/zAdBgNVHQ4EFgQUfEKWrt5LSDv6kviejM9ti6lyN5UwCgYIKoZI
        zj0EAwMDaAAwZQIwe3lORlCEwkSHRhtFcP9Ymd70/aTSVaYgLXTWNLxBo1BfASdW
        tL4ndQavEi51mI38AjEAi/V3bNTIZargCyzuFJ0nN6T5U6VR5CmD1/iQMVtCnwr1
        /q4AaOeMSQ+2b1tbFfLn
        """

    /// Base64 SHA-256 of `isrgRootX2DER`'s SubjectPublicKeyInfo, derived with the openssl
    /// pipeline documented on the enum.
    static let isrgRootX2SPKI = "diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI="

    // MARK: - Generated throwaway RSA PKI (no private key committed)

    /// Self-signed test root CA, RSA 2048, valid 2026-09-06 → 2046-09-01.
    static let rsa2048RootDER = """
        MIIDNzCCAh+gAwIBAgIUN3mkC9nN8tm1eT2q4YRL3f6VeRIwDQYJKoZIhvcNAQEL
        BQAwKzEpMCcGA1UEAwwgVm91Y2hmbG93IFNESyBUZXN0IFJTQS0yMDQ4IFJvb3Qw
        HhcNMjYwOTA2MjMxMzEzWhcNNDYwOTAxMjMxMzEzWjArMSkwJwYDVQQDDCBWb3Vj
        aGZsb3cgU0RLIFRlc3QgUlNBLTIwNDggUm9vdDCCASIwDQYJKoZIhvcNAQEBBQAD
        ggEPADCCAQoCggEBALMGa1uXbtdcW/UcHBNY8rBo0xUZh9idWgCI2eacnIODY365
        ha/T90MMBJE1ih4YXeQYQN8Keky9qOS1I8SJzx1gAnpMiohaLpNSFiC+5nWR8ZzP
        OwMXSQAh+xzo9QXc237nUPVRCHBAzOCC3j7Nu9NW1eRNtqk63trW3rKGt8UKf4wP
        NNerll6iUilYRV+CeRzv7k4ZN/4GgY0WRWu47XPveW5QFFWFxv+rVHhB5yZe+qtV
        L6EjC/NLbyyR0h/8ypRtp4VBImxMc4EMxvHmgD38y6HAdIBJw8JZ8CTWMzQtyYqw
        AHl/J6Zb01rCNy9CDXHhQCECKIAmjIdQTWP0cu0CAwEAAaNTMFEwHQYDVR0OBBYE
        FINvKluL+lHYPp6FA/bdRu8E66zWMB8GA1UdIwQYMBaAFINvKluL+lHYPp6FA/bd
        Ru8E66zWMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAETNs5/3
        4YDsccF1ByjSOIb8WpA56vYUSOHuSK4mUZksxekwNvCT3damtkiOIZgm0H4xdkNC
        FdqYpJqI9/zToRp3ffk+rk1NMQDqQtfZ9WC5C5oJvePEGqiZVeEkxOgnaWjEdWey
        m56Vr7Imptc91HO7cfetuHfSz4FvCi7T0XfD/Uu+u8GaM27tsEn9n5mwhwAZTpno
        GLip51WV3ho7BHnJDoujNwCDjAda4aETV4Pv/yRHSMnTPqRjfdjtnH2PWn5XiG4u
        MRX+0+UxkhlRLI38fxKl4VGng+65pb46Z6/O/aXQfPBwQ6okBuh9+rhuyMZUi/wb
        yJTMOltV123u2k8=
        """

    /// Base64 SHA-256 of `rsa2048RootDER`'s SubjectPublicKeyInfo (openssl pipeline).
    static let rsa2048RootSPKI = "r07cbBeOgXlSC64dCNRJ2bWFIzPUkkYdYGmZbXJfShA="

    /// Self-signed test root CA, RSA 3072, valid 2026-09-06 → 2046-09-01.
    static let rsa3072RootDER = """
        MIIENzCCAp+gAwIBAgIUb01IRuUEWpFXVjtlOrLav48Nh+MwDQYJKoZIhvcNAQEL
        BQAwKzEpMCcGA1UEAwwgVm91Y2hmbG93IFNESyBUZXN0IFJTQS0zMDcyIFJvb3Qw
        HhcNMjYwOTA2MjMxMzEzWhcNNDYwOTAxMjMxMzEzWjArMSkwJwYDVQQDDCBWb3Vj
        aGZsb3cgU0RLIFRlc3QgUlNBLTMwNzIgUm9vdDCCAaIwDQYJKoZIhvcNAQEBBQAD
        ggGPADCCAYoCggGBAKHvEJqTZxbL+acFTPJVjRrcpgJX3K4cWTEIR3RreYTTknbe
        ir2rSKl3qB4KT5d7mlrus4GWkDZAotagisedE7XeuND44VoMCewNBYhJ/oqMEi6E
        bvwYBGq+3n7OcPX1KBYInxFZy/PNDo48ZNUIAKXYTIo6kKd7cK7WPMPvJTyMP54x
        rkoxvIzJcNJJWXCiyStW2bdWG/vcOeOvBn1H3HdvlEOI21ZBshmJ9Hmy8734T+BG
        S6Nf/ZHWrWZ/3lFr0APA6vfsGmzK2SmGjxi5d4igihmAzossDgNfrZMf/l2iMRm4
        XxovDCmZQfzAJtN6qXVZBoxo5LtcJhb0YvF3/3W/Qt6GnL1U4/RH76ODdg+TGHu/
        SD3OftIkjT6UHX5oV3LNsZcVk4hu4rpzFXxV7dgseraTY8m3m/sB+1TtYrRbVXVF
        B4XkXQe/7oN+uThRPhnI6kl8o3JpP6OqYDEMLg+vWCcjxtqIIDFPVFowh6eRpUIR
        qp8SmlZgLF/O/ah/LQIDAQABo1MwUTAdBgNVHQ4EFgQUqfNdq+NFGOAyZRyb/NmE
        NtPKilYwHwYDVR0jBBgwFoAUqfNdq+NFGOAyZRyb/NmENtPKilYwDwYDVR0TAQH/
        BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAYEABrzQQzlmzJtHYvxLqLEazWRYgcSN
        n3Bkuy3qPu+sdRzSsqnUnxEdH14TnNwizLiS/LRff1pWOm5zaDxxvHdocFufN9ZM
        9B9RWQCxeeTtU3YMwLjy5aqA2Z1H786U8gqUIRWuGvmvq4n3x74x6qzh53Hn6nDd
        aRCbCRxoNZn8/4gt1KqxjX+P1nXTw31gKJ4Qr4XoEAX7FYP+g7FuFjSIyUvYSzOL
        qIrm0s94nVr+fGctDmd+bcRdqMeq21NzkO6GhGCyeQVkW9+pBdHdU8xrPAV0sTnn
        KQG+A0o2g2JRaDGbLLDPScTmzBSoD+RPKFn0rINWIFXqmE0cc2C2aTwHGNyI/iIG
        tmfB9AFVJFG1nQd8c0TkR4Dr/axoCIZFhlXLrtO/q7byOeIJVdrYfPxc+64lEiqp
        kDVRy4LnO18YbKYKIlawx/0pXsCBhw0sysbl9DjA7EykrALR+aPJumbQor86T54m
        vH3sNO6A82zFG3HH+fwovLrOKkjdvjPvdUB4
        """

    /// Base64 SHA-256 of `rsa3072RootDER`'s SubjectPublicKeyInfo (openssl pipeline).
    static let rsa3072RootSPKI = "tD1gZumW3eS364gEBavB2C9dRyLqo6Rnp1nYIbBBEWg="

    /// Self-signed test root CA, RSA 4096, valid 2026-09-06 → 2046-09-01. Stands in for
    /// ISRG Root X1 in the end-to-end `decision(forServerTrust:)` tests, so acceptance can
    /// be asserted at a fixed `verifyDate` against a chain built entirely from fixtures.
    static let rsa4096RootDER = """
        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
        """

    /// Base64 SHA-256 of `rsa4096RootDER`'s SubjectPublicKeyInfo (openssl pipeline).
    static let rsa4096RootSPKI = "uU18NGACradunb/NJXsUtmUmU2NSDWZEOB9u/xg1aUo="

    /// EC P-256 leaf for `api.vouchflow.dev` issued by `rsa4096RootDER`, valid
    /// 2026-09-06 → 2027-09-01 — a mixed-algorithm chain (EC leaf, RSA root), the shape
    /// an RSA-pinned Let's Encrypt deployment serves.
    static let rsaChainLeafDER = """
        MIIDnzCCAYegAwIBAgIUO70hnmqzeaApCIniS7T1W2OLvRowDQYJKoZIhvcNAQEL
        BQAwKzEpMCcGA1UEAwwgVm91Y2hmbG93IFNESyBUZXN0IFJTQS00MDk2IFJvb3Qw
        HhcNMjYwOTA2MjMxMzI1WhcNMjcwOTAxMjMxMzI1WjAcMRowGAYDVQQDDBFhcGku
        dm91Y2hmbG93LmRldjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJwVPKDT1Y59
        Z0YHJ5umOiqYZeEUYMwDvaMpG8ygKrDJ291YSRG+bod3UJ591IrSukIiZ+uJnVnM
        tTq4pOhrL3mjgZQwgZEwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBaAwEwYD
        VR0lBAwwCgYIKwYBBQUHAwEwHAYDVR0RBBUwE4IRYXBpLnZvdWNoZmxvdy5kZXYw
        HQYDVR0OBBYEFOKW8UhnFIJaQHsf4SsWm/NE1HlWMB8GA1UdIwQYMBaAFOHZoLeU
        60qmCB0SMG08RseHwHcpMA0GCSqGSIb3DQEBCwUAA4ICAQApNXKVd+wCqsOvLrvi
        QsW9s25blhenFG1XOx+/U1w8TzsrLzqXeRSDjPp6O1XEodbNtTamFVZLvqwZbtxy
        cB/sz/rAWMVWmbYZtTUrPYma4O8BwhyHuGuG/luP5Obm8ausJ8zyeHSxZqR4Brs6
        844Qh9Pux5u/HqIqVAQ32bxR/rcNfkxDivOobqU9t24OAkCrypvuin2zOwNwr1TN
        gCJ7P8Nqh3NpLOBnkKONvvuWPrcVoX/G7lRI2jrGpJCTXJ2ZJAdapa+RjY7GeVik
        t8gOwddwUl8WrvxVM+Re0oGrLkZBthH0D/whL3gUUCeNcNx/MyNW8+iAocRH3uon
        uaINwngzJaE4pRCVr1L0OvlW+B0lF81Uts+v1K4l1RjZc9lSsI2x/51pN4xuywef
        zDfcMs55Oa1qQb3CSAXWmAy2ycf2oNd7e4xqV2onyfuWNmdw/ug/A72qc6S+ji0o
        spcW/vLe4HFYZ1kJyqWWfPAc2qFopxcAnwCZJTIznSH9PAIBYsmRpESmS2wDyyu6
        VoX4lvxCucZQOdnvcpswWCcpELOY4TF86BH9S1t1A+fKoVvaFcPO7sM/KIyS75Yt
        K/kYaP65Qiynh7dewVFf8hKNse/aaF/ss9A1oHrNiVGgsIxst4ggqmbl4uJx3iNK
        xY0L9+BO31G+P2wzF8wchWrqlg==
        """

    /// Base64 SHA-256 of `rsaChainLeafDER`'s SubjectPublicKeyInfo (openssl pipeline).
    static let rsaChainLeafSPKI = "wjMW2R1oMWypGvNkWxrmNCo5ez1mfXjwsX4vhy1jP2Q="
}

import CryptoKit

/// An independent ASN.1 walk of a DER X.509 certificate that extracts the raw
/// `subjectPublicKeyInfo` element — deliberately implemented here, in the test target,
/// without sharing any code with `PinningDelegate`'s key-representation logic, so that the
/// SDK's SPKI assembly is checked against a second opinion rather than against itself.
enum IndependentSPKI {

    /// Returns the complete `subjectPublicKeyInfo` element (from its SEQUENCE tag through
    /// its end) of a DER `Certificate`. Hashing exactly these bytes with SHA-256 is the
    /// definition of the pin value.
    static func spkiBytes(ofCertificateDER der: Data) -> Data? {
        let bytes = [UInt8](der)

        // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
        guard let certificate = readTLV(bytes, at: 0), certificate.tag == 0x30,
              let tbs = readTLV(bytes, at: certificate.contentStart), tbs.tag == 0x30 else {
            return nil
        }

        // tbsCertificate ::= SEQUENCE { version [0] EXPLICIT OPTIONAL, serialNumber,
        //     signature, issuer, validity, subject, subjectPublicKeyInfo, ... }
        var cursor = tbs.contentStart
        var elementIndex = 0
        while cursor < tbs.contentEnd {
            guard let element = readTLV(bytes, at: cursor) else { return nil }
            if elementIndex == 0 && element.tag == 0xA0 {
                cursor = element.end // explicit version tag — skip, it is not one of the six
                continue
            }
            elementIndex += 1
            if elementIndex == 6 {
                // serial (0x02), signature (0x30), issuer (0x30), validity (0x30),
                // subject (0x30) — the next element is the subjectPublicKeyInfo.
                guard element.tag == 0x30 else { return nil }
                return Data(bytes[element.start ..< element.end])
            }
            cursor = element.end
        }
        return nil
    }

    /// SHA-256 SPKI pin of a DER certificate, computed via the independent walk.
    static func spkiPin(ofCertificateDER der: Data) -> String? {
        guard let spki = spkiBytes(ofCertificateDER: der) else { return nil }
        return Data(SHA256.hash(data: spki)).base64EncodedString()
    }

    // MARK: - Minimal DER TLV reader

    private struct TLV {
        let tag: UInt8
        let start: Int       // tag position — the element includes tag + length + content
        let contentStart: Int
        let contentEnd: Int
        let end: Int
    }

    private static func readTLV(_ bytes: [UInt8], at index: Int) -> TLV? {
        guard index + 2 <= bytes.count else { return nil }
        let tag = bytes[index]
        var cursor = index + 1
        let firstLengthByte = bytes[cursor]
        cursor += 1
        var length: Int
        if firstLengthByte < 0x80 {
            length = Int(firstLengthByte)
        } else {
            let byteCount = Int(firstLengthByte & 0x7F)
            guard byteCount >= 1, byteCount <= 4, cursor + byteCount <= bytes.count else { return nil }
            length = 0
            for _ in 0 ..< byteCount {
                length = (length << 8) | Int(bytes[cursor])
                cursor += 1
            }
        }
        let contentStart = cursor
        let contentEnd = contentStart + length
        guard contentEnd <= bytes.count else { return nil }
        return TLV(tag: tag, start: index, contentStart: contentStart, contentEnd: contentEnd, end: contentEnd)
    }
}
