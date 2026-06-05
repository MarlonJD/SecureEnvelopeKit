import CryptoKit
import Foundation
import Security

public enum SecureEnvelopeError: Error, Equatable, Sendable, CustomStringConvertible {
    case malformedEnvelope
    case unsupportedVersion(UInt8)
    case unsupportedSuite(UInt16)
    case invalidKeyMaterial
    case invalidMetadata
    case authenticationFailed
    case randomnessUnavailable
    case previewPayloadTooLarge

    public var description: String {
        switch self {
        case .malformedEnvelope:
            return "Malformed secure envelope."
        case .unsupportedVersion:
            return "Unsupported secure envelope version."
        case .unsupportedSuite:
            return "Unsupported secure envelope suite."
        case .invalidKeyMaterial:
            return "Invalid secure envelope key material."
        case .invalidMetadata:
            return "Invalid secure envelope metadata."
        case .authenticationFailed:
            return "Secure envelope authentication failed."
        case .randomnessUnavailable:
            return "Secure randomness is unavailable."
        case .previewPayloadTooLarge:
            return "Secure envelope preview payload is too large."
        }
    }
}

public enum SecureEnvelopeSuite: UInt16, CaseIterable, Sendable {
    case v1AES256GCMHKDFSHA256 = 0x0001
}

public struct SecureEnvelopeMetadata: Equatable, Sendable {
    public let keyIdentifier: Data
    public let publicContext: Data

    public init(keyIdentifier: Data, publicContext: Data = Data()) {
        self.keyIdentifier = keyIdentifier
        self.publicContext = publicContext
    }
}

public struct SecureEnvelope: Equatable, Sendable {
    public let version: UInt8
    public let suite: SecureEnvelopeSuite
    public let metadata: SecureEnvelopeMetadata
    public let salt: Data
    public let nonce: Data
    public let ciphertext: Data
    public let tag: Data
    public let serializedData: Data

    let authenticatedHeader: Data

    public init(serializedData: Data) throws {
        let decoded = try SecureEnvelopeWireFormat.decode(serializedData)
        try self.init(
            version: decoded.version,
            suite: decoded.suite,
            metadata: decoded.metadata,
            salt: decoded.salt,
            nonce: decoded.nonce,
            ciphertext: decoded.ciphertext,
            tag: decoded.tag
        )

        guard self.serializedData == serializedData else {
            throw SecureEnvelopeError.malformedEnvelope
        }
    }

    init(
        version: UInt8 = SecureEnvelopeWireFormat.version,
        suite: SecureEnvelopeSuite = .v1AES256GCMHKDFSHA256,
        metadata: SecureEnvelopeMetadata,
        salt: Data,
        nonce: Data,
        ciphertext: Data,
        tag: Data
    ) throws {
        try SecureEnvelopeWireFormat.validateMetadata(metadata)
        guard version == SecureEnvelopeWireFormat.version else {
            throw SecureEnvelopeError.unsupportedVersion(version)
        }
        guard salt.count == SecureEnvelopeWireFormat.saltByteCount,
              nonce.count == SecureEnvelopeWireFormat.nonceByteCount,
              tag.count == SecureEnvelopeWireFormat.tagByteCount else {
            throw SecureEnvelopeError.malformedEnvelope
        }

        let header = try SecureEnvelopeWireFormat.headerBytes(
            version: version,
            suite: suite,
            metadata: metadata,
            salt: salt,
            nonce: nonce,
            ciphertextByteCount: ciphertext.count,
            tagByteCount: tag.count
        )

        var serialized = Data()
        serialized.reserveCapacity(header.count + ciphertext.count + tag.count)
        serialized.append(header)
        serialized.append(ciphertext)
        serialized.append(tag)

        self.version = version
        self.suite = suite
        self.metadata = metadata
        self.salt = salt
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.tag = tag
        self.authenticatedHeader = header
        self.serializedData = serialized
    }
}

public struct SecureEnvelopeSealer {
    private let randomBytes: (Int) throws -> Data

    public init() {
        self.randomBytes = SecureRandom.bytes(count:)
    }

    init(randomBytes: @escaping (Int) throws -> Data) {
        self.randomBytes = randomBytes
    }

    public func seal(
        plaintext: Data,
        keyMaterial: Data,
        metadata: SecureEnvelopeMetadata
    ) throws -> SecureEnvelope {
        let salt = try randomBytes(SecureEnvelopeWireFormat.saltByteCount)
        let nonce = try randomBytes(SecureEnvelopeWireFormat.nonceByteCount)
        return try seal(
            plaintext: plaintext,
            keyMaterial: keyMaterial,
            metadata: metadata,
            salt: salt,
            nonce: nonce
        )
    }

    func seal(
        plaintext: Data,
        keyMaterial: Data,
        metadata: SecureEnvelopeMetadata,
        salt: Data,
        nonce: Data
    ) throws -> SecureEnvelope {
        try SecureEnvelopeCrypto.validateKeyMaterial(keyMaterial)
        try SecureEnvelopeWireFormat.validateMetadata(metadata)
        guard salt.count == SecureEnvelopeWireFormat.saltByteCount,
              nonce.count == SecureEnvelopeWireFormat.nonceByteCount else {
            throw SecureEnvelopeError.malformedEnvelope
        }

        let header = try SecureEnvelopeWireFormat.headerBytes(
            version: SecureEnvelopeWireFormat.version,
            suite: .v1AES256GCMHKDFSHA256,
            metadata: metadata,
            salt: salt,
            nonce: nonce,
            ciphertextByteCount: plaintext.count,
            tagByteCount: SecureEnvelopeWireFormat.tagByteCount
        )
        let key = try SecureEnvelopeCrypto.deriveContentKey(
            keyMaterial: keyMaterial,
            salt: salt,
            suite: .v1AES256GCMHKDFSHA256
        )
        let sealed = try SecureEnvelopeCrypto.seal(
            plaintext: plaintext,
            key: key,
            nonceData: nonce,
            authenticatedData: header
        )

        return try SecureEnvelope(
            metadata: metadata,
            salt: salt,
            nonce: nonce,
            ciphertext: sealed.ciphertext,
            tag: sealed.tag
        )
    }
}

public struct SecureEnvelopeOpener {
    public init() {}

    public func open(serializedData: Data, keyMaterial: Data) throws -> Data {
        let envelope = try SecureEnvelope(serializedData: serializedData)
        return try open(envelope: envelope, keyMaterial: keyMaterial)
    }

    public func open(envelope: SecureEnvelope, keyMaterial: Data) throws -> Data {
        try SecureEnvelopeCrypto.validateKeyMaterial(keyMaterial)
        let key = try SecureEnvelopeCrypto.deriveContentKey(
            keyMaterial: keyMaterial,
            salt: envelope.salt,
            suite: envelope.suite
        )
        return try SecureEnvelopeCrypto.open(
            ciphertext: envelope.ciphertext,
            tag: envelope.tag,
            key: key,
            nonceData: envelope.nonce,
            authenticatedData: envelope.authenticatedHeader
        )
    }
}

public struct SecureEnvelopePreviewResult: Equatable, Sendable {
    public let metadata: SecureEnvelopeMetadata
    public let plaintext: Data

    public init(metadata: SecureEnvelopeMetadata, plaintext: Data) {
        self.metadata = metadata
        self.plaintext = plaintext
    }
}

/// Preview-safe helper for small caller-provided preview envelopes.
///
/// The helper bounds serialized envelope, public metadata, and plaintext bytes.
/// Parsed metadata remains an untrusted routing hint until AEAD verification
/// succeeds with the expected key material.
public struct SecureEnvelopePreview {
    public let maxPlaintextBytes: Int
    public let maxSerializedEnvelopeBytes: Int
    public let maxPublicMetadataBytes: Int

    public init(
        maxPlaintextBytes: Int = 4096,
        maxSerializedEnvelopeBytes: Int = 16 * 1024,
        maxPublicMetadataBytes: Int = 1024
    ) {
        self.maxPlaintextBytes = maxPlaintextBytes
        self.maxSerializedEnvelopeBytes = maxSerializedEnvelopeBytes
        self.maxPublicMetadataBytes = maxPublicMetadataBytes
    }

    public func open(serializedData: Data, keyMaterial: Data) throws -> SecureEnvelopePreviewResult {
        guard maxSerializedEnvelopeBytes >= 0,
              serializedData.count <= maxSerializedEnvelopeBytes else {
            throw SecureEnvelopeError.previewPayloadTooLarge
        }

        let envelope = try SecureEnvelope(serializedData: serializedData)
        let keyIdentifierByteCount = envelope.metadata.keyIdentifier.count
        let publicContextByteCount = envelope.metadata.publicContext.count
        guard maxPublicMetadataBytes >= 0,
              keyIdentifierByteCount <= maxPublicMetadataBytes,
              publicContextByteCount <= maxPublicMetadataBytes - keyIdentifierByteCount,
              maxPlaintextBytes >= 0,
              envelope.ciphertext.count <= maxPlaintextBytes else {
            throw SecureEnvelopeError.previewPayloadTooLarge
        }

        let plaintext = try SecureEnvelopeOpener().open(envelope: envelope, keyMaterial: keyMaterial)
        guard plaintext.count <= maxPlaintextBytes else {
            throw SecureEnvelopeError.previewPayloadTooLarge
        }

        return SecureEnvelopePreviewResult(metadata: envelope.metadata, plaintext: plaintext)
    }
}

enum SecureEnvelopeCrypto {
    static let minimumKeyMaterialByteCount = 32

    static func validateKeyMaterial(_ keyMaterial: Data) throws {
        guard keyMaterial.count >= minimumKeyMaterialByteCount else {
            throw SecureEnvelopeError.invalidKeyMaterial
        }
    }

    static func deriveContentKey(
        keyMaterial: Data,
        salt: Data,
        suite: SecureEnvelopeSuite
    ) throws -> SymmetricKey {
        try validateKeyMaterial(keyMaterial)
        guard salt.count == SecureEnvelopeWireFormat.saltByteCount else {
            throw SecureEnvelopeError.malformedEnvelope
        }

        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: keyMaterial),
            salt: salt,
            info: hkdfInfo(for: suite),
            outputByteCount: 32
        )
    }

    static func deriveContentKeyBytes(
        keyMaterial: Data,
        salt: Data,
        suite: SecureEnvelopeSuite
    ) throws -> Data {
        let key = try deriveContentKey(keyMaterial: keyMaterial, salt: salt, suite: suite)
        return key.withUnsafeBytes { Data($0) }
    }

    static func seal(
        plaintext: Data,
        key: SymmetricKey,
        nonceData: Data,
        authenticatedData: Data
    ) throws -> (ciphertext: Data, tag: Data) {
        let nonce = try AES.GCM.Nonce(data: nonceData)
        let sealedBox = try AES.GCM.seal(
            plaintext,
            using: key,
            nonce: nonce,
            authenticating: authenticatedData
        )
        return (sealedBox.ciphertext, sealedBox.tag)
    }

    static func open(
        ciphertext: Data,
        tag: Data,
        key: SymmetricKey,
        nonceData: Data,
        authenticatedData: Data
    ) throws -> Data {
        do {
            let nonce = try AES.GCM.Nonce(data: nonceData)
            let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
            return try AES.GCM.open(sealedBox, using: key, authenticating: authenticatedData)
        } catch {
            throw SecureEnvelopeError.authenticationFailed
        }
    }

    private static func hkdfInfo(for suite: SecureEnvelopeSuite) -> Data {
        switch suite {
        case .v1AES256GCMHKDFSHA256:
            return Data("SecureEnvelopeKit/v1/aes-256-gcm+hkdf-sha256".utf8)
        }
    }
}

enum SecureEnvelopeWireFormat {
    static let magic: [UInt8] = [0x53, 0x45, 0x4B]
    static let version: UInt8 = 1
    static let saltByteCount = 32
    static let nonceByteCount = 12
    static let tagByteCount = 16

    struct Decoded {
        let version: UInt8
        let suite: SecureEnvelopeSuite
        let metadata: SecureEnvelopeMetadata
        let salt: Data
        let nonce: Data
        let ciphertext: Data
        let tag: Data
    }

    static func validateMetadata(_ metadata: SecureEnvelopeMetadata) throws {
        guard !metadata.keyIdentifier.isEmpty,
              metadata.keyIdentifier.count <= Int(UInt16.max) else {
            throw SecureEnvelopeError.invalidMetadata
        }
        guard metadata.publicContext.count <= Int(UInt32.max) else {
            throw SecureEnvelopeError.invalidMetadata
        }
    }

    static func headerBytes(
        version: UInt8,
        suite: SecureEnvelopeSuite,
        metadata: SecureEnvelopeMetadata,
        salt: Data,
        nonce: Data,
        ciphertextByteCount: Int,
        tagByteCount: Int
    ) throws -> Data {
        try validateMetadata(metadata)
        guard ciphertextByteCount <= Int(UInt32.max) else {
            throw SecureEnvelopeError.malformedEnvelope
        }
        guard salt.count == saltByteCount,
              nonce.count == nonceByteCount,
              tagByteCount == self.tagByteCount else {
            throw SecureEnvelopeError.malformedEnvelope
        }

        var data = Data()
        data.reserveCapacity(
            magic.count
                + 1
                + 2
                + 2 + metadata.keyIdentifier.count
                + 4 + metadata.publicContext.count
                + 1 + salt.count
                + 1 + nonce.count
                + 4
                + 1
        )
        data.append(contentsOf: magic)
        data.appendUInt8(version)
        data.appendUInt16(suite.rawValue)
        data.appendUInt16(UInt16(metadata.keyIdentifier.count))
        data.append(metadata.keyIdentifier)
        data.appendUInt32(UInt32(metadata.publicContext.count))
        data.append(metadata.publicContext)
        data.appendUInt8(UInt8(salt.count))
        data.append(salt)
        data.appendUInt8(UInt8(nonce.count))
        data.append(nonce)
        data.appendUInt32(UInt32(ciphertextByteCount))
        data.appendUInt8(UInt8(tagByteCount))
        return data
    }

    static func decode(_ data: Data) throws -> Decoded {
        var decoder = SecureEnvelopeBinaryDecoder(data: data)

        let magicBytes = try decoder.readBytes(count: magic.count)
        guard Array(magicBytes) == magic else {
            throw SecureEnvelopeError.malformedEnvelope
        }

        let decodedVersion = try decoder.readUInt8()
        guard decodedVersion == version else {
            throw SecureEnvelopeError.unsupportedVersion(decodedVersion)
        }

        let suiteRawValue = try decoder.readUInt16()
        guard let suite = SecureEnvelopeSuite(rawValue: suiteRawValue) else {
            throw SecureEnvelopeError.unsupportedSuite(suiteRawValue)
        }

        let keyIdentifier = try decoder.readLengthPrefixedData(lengthByteCount: 2)
        guard !keyIdentifier.isEmpty else {
            throw SecureEnvelopeError.malformedEnvelope
        }

        let publicContext = try decoder.readLengthPrefixedData(lengthByteCount: 4)

        let saltLength = Int(try decoder.readUInt8())
        let salt = try decoder.readBytes(count: saltLength)
        guard salt.count == saltByteCount else {
            throw SecureEnvelopeError.malformedEnvelope
        }

        let nonceLength = Int(try decoder.readUInt8())
        let nonce = try decoder.readBytes(count: nonceLength)
        guard nonce.count == nonceByteCount else {
            throw SecureEnvelopeError.malformedEnvelope
        }

        let ciphertextLength = Int(try decoder.readUInt32())
        let tagLength = Int(try decoder.readUInt8())
        guard tagLength == tagByteCount else {
            throw SecureEnvelopeError.malformedEnvelope
        }

        let headerLength = decoder.offset
        let ciphertext = try decoder.readBytes(count: ciphertextLength)
        let tag = try decoder.readBytes(count: tagLength)
        guard decoder.isAtEnd else {
            throw SecureEnvelopeError.malformedEnvelope
        }

        let metadata = SecureEnvelopeMetadata(keyIdentifier: keyIdentifier, publicContext: publicContext)
        try validateMetadata(metadata)

        let header = try headerBytes(
            version: decodedVersion,
            suite: suite,
            metadata: metadata,
            salt: salt,
            nonce: nonce,
            ciphertextByteCount: ciphertext.count,
            tagByteCount: tag.count
        )
        guard header.count == headerLength else {
            throw SecureEnvelopeError.malformedEnvelope
        }

        return Decoded(
            version: decodedVersion,
            suite: suite,
            metadata: metadata,
            salt: salt,
            nonce: nonce,
            ciphertext: ciphertext,
            tag: tag
        )
    }
}

struct SecureEnvelopeBinaryDecoder {
    private let bytes: [UInt8]
    private(set) var offset: Int = 0

    var isAtEnd: Bool {
        offset == bytes.count
    }

    init(data: Data) {
        self.bytes = Array(data)
    }

    mutating func readUInt8() throws -> UInt8 {
        let data = try readBytes(count: 1)
        return data[data.startIndex]
    }

    mutating func readUInt16() throws -> UInt16 {
        let data = try readBytes(count: 2)
        return (UInt16(data[data.startIndex]) << 8)
            | UInt16(data[data.index(after: data.startIndex)])
    }

    mutating func readUInt32() throws -> UInt32 {
        let data = try readBytes(count: 4)
        var value: UInt32 = 0
        for byte in data {
            value = (value << 8) | UInt32(byte)
        }
        return value
    }

    mutating func readLengthPrefixedData(lengthByteCount: Int) throws -> Data {
        let length: Int
        switch lengthByteCount {
        case 2:
            length = Int(try readUInt16())
        case 4:
            length = Int(try readUInt32())
        default:
            throw SecureEnvelopeError.malformedEnvelope
        }
        return try readBytes(count: length)
    }

    mutating func readBytes(count: Int) throws -> Data {
        guard count >= 0,
              offset <= bytes.count,
              count <= bytes.count - offset else {
            throw SecureEnvelopeError.malformedEnvelope
        }

        let end = offset + count
        let data = Data(bytes[offset..<end])
        offset = end
        return data
    }
}

enum SecureRandom {
    static func bytes(count: Int) throws -> Data {
        guard count >= 0 else {
            throw SecureEnvelopeError.randomnessUnavailable
        }
        guard count > 0 else {
            return Data()
        }

        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { buffer in
            guard let baseAddress = buffer.baseAddress else {
                return errSecParam
            }
            return SecRandomCopyBytes(kSecRandomDefault, count, baseAddress)
        }
        guard status == errSecSuccess else {
            throw SecureEnvelopeError.randomnessUnavailable
        }
        return data
    }
}

private extension Data {
    mutating func appendUInt8(_ value: UInt8) {
        append(value)
    }

    mutating func appendUInt16(_ value: UInt16) {
        append(UInt8((value >> 8) & 0xff))
        append(UInt8(value & 0xff))
    }

    mutating func appendUInt32(_ value: UInt32) {
        append(UInt8((value >> 24) & 0xff))
        append(UInt8((value >> 16) & 0xff))
        append(UInt8((value >> 8) & 0xff))
        append(UInt8(value & 0xff))
    }
}
