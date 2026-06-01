@testable import SecureEnvelopeKit
import XCTest

final class SecureEnvelopeKitTests: XCTestCase {
    private let keyMaterial = Data((0..<32).map { UInt8($0) })
    private let wrongKeyMaterial = Data((64..<96).map { UInt8($0) })
    private let salt = Data((32..<64).map { UInt8($0) })
    private let nonce = Data((96..<108).map { UInt8($0) })
    private let metadata = SecureEnvelopeMetadata(
        keyIdentifier: Data("key-1".utf8),
        publicContext: Data("preview".utf8)
    )
    private let plaintext = Data("hello secure envelope".utf8)

    func testSealAndOpenRoundTrip() throws {
        let envelope = try deterministicEnvelope()

        let opened = try SecureEnvelopeOpener().open(envelope: envelope, keyMaterial: keyMaterial)

        XCTAssertEqual(opened, plaintext)
        XCTAssertEqual(envelope.version, 1)
        XCTAssertEqual(envelope.suite, .v1AES256GCMHKDFSHA256)
        XCTAssertEqual(envelope.metadata, metadata)
    }

    func testOpeningWithWrongKeyFailsAuthentication() throws {
        let envelope = try deterministicEnvelope()

        XCTAssertThrowsSecureEnvelopeError(.authenticationFailed) {
            _ = try SecureEnvelopeOpener().open(envelope: envelope, keyMaterial: wrongKeyMaterial)
        }
    }

    func testTamperedHeaderFailsAuthentication() throws {
        let envelope = try deterministicEnvelope()
        var tampered = envelope.serializedData
        let firstKeyIdentifierByteOffset = 8
        tampered[firstKeyIdentifierByteOffset] ^= 0x01

        let parsed = try SecureEnvelope(serializedData: tampered)
        XCTAssertThrowsSecureEnvelopeError(.authenticationFailed) {
            _ = try SecureEnvelopeOpener().open(envelope: parsed, keyMaterial: keyMaterial)
        }
    }

    func testTamperedCiphertextFailsAuthentication() throws {
        let envelope = try deterministicEnvelope()
        var tampered = envelope.serializedData
        tampered[envelope.authenticatedHeader.count] ^= 0x01

        let parsed = try SecureEnvelope(serializedData: tampered)
        XCTAssertThrowsSecureEnvelopeError(.authenticationFailed) {
            _ = try SecureEnvelopeOpener().open(envelope: parsed, keyMaterial: keyMaterial)
        }
    }

    func testTamperedTagFailsAuthentication() throws {
        let envelope = try deterministicEnvelope()
        var tampered = envelope.serializedData
        tampered[tampered.index(before: tampered.endIndex)] ^= 0x01

        let parsed = try SecureEnvelope(serializedData: tampered)
        XCTAssertThrowsSecureEnvelopeError(.authenticationFailed) {
            _ = try SecureEnvelopeOpener().open(envelope: parsed, keyMaterial: keyMaterial)
        }
    }

    func testMalformedEnvelopeDecodeFailures() throws {
        let envelope = try deterministicEnvelope()

        XCTAssertThrowsSecureEnvelopeError(.malformedEnvelope) {
            _ = try SecureEnvelope(serializedData: envelope.serializedData.dropLast())
        }

        var trailing = envelope.serializedData
        trailing.append(0xff)
        XCTAssertThrowsSecureEnvelopeError(.malformedEnvelope) {
            _ = try SecureEnvelope(serializedData: trailing)
        }

        var unsupportedVersion = envelope.serializedData
        unsupportedVersion[3] = 2
        XCTAssertThrowsSecureEnvelopeError(.unsupportedVersion(2)) {
            _ = try SecureEnvelope(serializedData: unsupportedVersion)
        }

        var unsupportedSuite = envelope.serializedData
        unsupportedSuite[4] = 0x7f
        unsupportedSuite[5] = 0xff
        XCTAssertThrowsSecureEnvelopeError(.unsupportedSuite(0x7fff)) {
            _ = try SecureEnvelope(serializedData: unsupportedSuite)
        }
    }

    func testStableBinaryEncodingFixture() throws {
        let envelope = try deterministicEnvelope()

        XCTAssertEqual(envelope.serializedData.hexEncodedString(), stableFixtureHex)
        XCTAssertEqual(try SecureEnvelope(serializedData: envelope.serializedData).serializedData, envelope.serializedData)
    }

    func testPreviewHelperReturnsCallerOwnedPreviewData() throws {
        let envelope = try deterministicEnvelope()
        let preview = SecureEnvelopePreview(maxPlaintextBytes: 64)

        let result = try preview.open(serializedData: envelope.serializedData, keyMaterial: keyMaterial)

        XCTAssertEqual(result.metadata, metadata)
        XCTAssertEqual(result.plaintext, plaintext)
    }

    func testPreviewHelperRejectsOversizedPayloadBeforeOpen() throws {
        let envelope = try deterministicEnvelope()
        let preview = SecureEnvelopePreview(maxPlaintextBytes: 4)

        XCTAssertThrowsSecureEnvelopeError(.previewPayloadTooLarge) {
            _ = try preview.open(serializedData: envelope.serializedData, keyMaterial: keyMaterial)
        }
    }

    func testHKDFDerivationIsDeterministic() throws {
        let first = try SecureEnvelopeCrypto.deriveContentKeyBytes(
            keyMaterial: keyMaterial,
            salt: salt,
            suite: .v1AES256GCMHKDFSHA256
        )
        let second = try SecureEnvelopeCrypto.deriveContentKeyBytes(
            keyMaterial: keyMaterial,
            salt: salt,
            suite: .v1AES256GCMHKDFSHA256
        )
        let differentSalt = try SecureEnvelopeCrypto.deriveContentKeyBytes(
            keyMaterial: keyMaterial,
            salt: Data((33..<65).map { UInt8($0) }),
            suite: .v1AES256GCMHKDFSHA256
        )

        XCTAssertEqual(first, second)
        XCTAssertNotEqual(first, differentSalt)
        XCTAssertEqual(first.hexEncodedString(), stableDerivedKeyHex)
    }

    func testInvalidInputsAreRejected() throws {
        XCTAssertThrowsSecureEnvelopeError(.invalidKeyMaterial) {
            _ = try SecureEnvelopeSealer().seal(
                plaintext: plaintext,
                keyMaterial: Data("too-short".utf8),
                metadata: metadata,
                salt: salt,
                nonce: nonce
            )
        }

        XCTAssertThrowsSecureEnvelopeError(.invalidMetadata) {
            _ = try SecureEnvelopeSealer().seal(
                plaintext: plaintext,
                keyMaterial: keyMaterial,
                metadata: SecureEnvelopeMetadata(keyIdentifier: Data()),
                salt: salt,
                nonce: nonce
            )
        }
    }

    private func deterministicEnvelope() throws -> SecureEnvelope {
        try SecureEnvelopeSealer().seal(
            plaintext: plaintext,
            keyMaterial: keyMaterial,
            metadata: metadata,
            salt: salt,
            nonce: nonce
        )
    }
}

private let stableFixtureHex = "53454b01000100056b65792d31000000077072657669657720202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f0c606162636465666768696a6b0000001510f9ed2ee278a37844640700bb1a3870151388432ef2ae8a56423081a3a8d0672d06eb5f6d0f"
private let stableDerivedKeyHex = "614aa5ec2c8bab156b0813ced2ab5d430aba2ee7989a0428e3c9507780770429"

private func XCTAssertThrowsSecureEnvelopeError(
    _ expectedError: SecureEnvelopeError,
    _ expression: () throws -> Void,
    file: StaticString = #filePath,
    line: UInt = #line
) {
    XCTAssertThrowsError(try expression(), file: file, line: line) { error in
        XCTAssertEqual(error as? SecureEnvelopeError, expectedError, file: file, line: line)
    }
}

private extension Data {
    func hexEncodedString() -> String {
        map { String(format: "%02x", $0) }.joined()
    }
}
