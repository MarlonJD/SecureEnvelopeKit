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
        let fixture = try SecureEnvelopeV1Fixture.load()
        let envelope = try deterministicEnvelope()

        XCTAssertEqual(fixture.version, 1)
        XCTAssertEqual(fixture.suiteIdHex, "0001")
        XCTAssertEqual(try fixture.hexData(fixture.keyMaterialHex), keyMaterial)
        XCTAssertEqual(try fixture.hexData(fixture.saltHex), salt)
        XCTAssertEqual(try fixture.hexData(fixture.nonceHex), nonce)
        XCTAssertEqual(try fixture.hexData(fixture.keyIdentifierHex), metadata.keyIdentifier)
        XCTAssertEqual(try fixture.hexData(fixture.publicContextHex), metadata.publicContext)
        XCTAssertEqual(try fixture.hexData(fixture.plaintextHex), plaintext)
        XCTAssertEqual(envelope.authenticatedHeader.hexEncodedString(), fixture.authenticatedHeaderHex)
        XCTAssertEqual(envelope.ciphertext.hexEncodedString(), fixture.ciphertextHex)
        XCTAssertEqual(envelope.tag.hexEncodedString(), fixture.tagHex)
        XCTAssertEqual(envelope.serializedData.hexEncodedString(), fixture.envelopeHex)
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

    func testPreviewHelperRejectsOversizedSerializedEnvelopeBeforeParse() throws {
        let envelope = try deterministicEnvelope()
        let preview = SecureEnvelopePreview(
            maxPlaintextBytes: 64,
            maxSerializedEnvelopeBytes: envelope.serializedData.count - 1
        )

        XCTAssertThrowsSecureEnvelopeError(.previewPayloadTooLarge) {
            _ = try preview.open(serializedData: envelope.serializedData, keyMaterial: wrongKeyMaterial)
        }
    }

    func testPreviewHelperRejectsOversizedPublicMetadataBeforeOpen() throws {
        let preview = SecureEnvelopePreview(
            maxPlaintextBytes: 64,
            maxSerializedEnvelopeBytes: 4096,
            maxPublicMetadataBytes: 4
        )
        let envelope = try deterministicEnvelope()

        XCTAssertThrowsSecureEnvelopeError(.previewPayloadTooLarge) {
            _ = try preview.open(serializedData: envelope.serializedData, keyMaterial: wrongKeyMaterial)
        }
    }

    func testHKDFDerivationIsDeterministic() throws {
        let fixture = try SecureEnvelopeV1Fixture.load()
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
        XCTAssertEqual(fixture.hkdfInfoUtf8, "SecureEnvelopeKit/v1/aes-256-gcm+hkdf-sha256")
        XCTAssertEqual(first.hexEncodedString(), fixture.derivedContentKeyHex)
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

private struct SecureEnvelopeV1Fixture: Decodable {
    let fixtureVersion: Int
    let status: String
    let name: String
    let version: Int
    let suite: String
    let suiteIdHex: String
    let hkdfInfoUtf8: String
    let keyMaterialHex: String
    let saltHex: String
    let nonceHex: String
    let keyIdentifierHex: String
    let publicContextHex: String
    let plaintextHex: String
    let authenticatedHeaderHex: String
    let ciphertextHex: String
    let tagHex: String
    let envelopeHex: String
    let derivedContentKeyHex: String

    static func load() throws -> SecureEnvelopeV1Fixture {
        // This test file lives at platforms/swift/Tests/SecureEnvelopeKitTests/.
        // Walk up to the SecureEnvelopeKit repository root, where the shared
        // cross-platform fixtures live under fixtures/.
        let testFileURL = URL(fileURLWithPath: #filePath)
        let repositoryRootURL = testFileURL
            .deletingLastPathComponent() // SecureEnvelopeKitTests/
            .deletingLastPathComponent() // Tests/
            .deletingLastPathComponent() // platforms/swift/
            .deletingLastPathComponent() // platforms/
            .deletingLastPathComponent() // repository root
        let fixtureURL = repositoryRootURL
            .appendingPathComponent("fixtures")
            .appendingPathComponent("SecureEnvelopeV1")
            .appendingPathComponent("secure-envelope-v1.json")
        let data = try Data(contentsOf: fixtureURL)
        let fixture = try JSONDecoder().decode(SecureEnvelopeV1Fixture.self, from: data)
        XCTAssertEqual(fixture.fixtureVersion, 1)
        XCTAssertEqual(fixture.status, "stable")
        XCTAssertEqual(fixture.name, "secure-envelope-v1-aes-256-gcm-hkdf-sha256")
        XCTAssertEqual(fixture.suite, "v1AES256GCMHKDFSHA256")
        return fixture
    }

    func hexData(_ hex: String) throws -> Data {
        try Data(hexEncodedString: hex)
    }
}

private extension Data {
    init(hexEncodedString hex: String) throws {
        guard hex.count.isMultiple(of: 2) else {
            throw SecureEnvelopeError.malformedEnvelope
        }

        var bytes = [UInt8]()
        bytes.reserveCapacity(hex.count / 2)

        var index = hex.startIndex
        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<nextIndex], radix: 16) else {
                throw SecureEnvelopeError.malformedEnvelope
            }
            bytes.append(byte)
            index = nextIndex
        }

        self = Data(bytes)
    }

    func hexEncodedString() -> String {
        map { String(format: "%02x", $0) }.joined()
    }
}
