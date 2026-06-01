package io.github.marlonjd.secureenvelope

import java.io.ByteArrayOutputStream
import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Product-independent secure envelope implementation for Android/JVM.
 *
 * This is the Android platform of the SecureEnvelopeKit monorepo. It conforms
 * to the language-neutral contract in `docs/spec/secure-envelope-v1.md` and the
 * shared fixture in `fixtures/SecureEnvelopeV1/`, so envelopes interoperate with
 * the Swift and .NET implementations.
 *
 * The package uses only provider-backed JCA primitives: `AES/GCM/NoPadding` for
 * AES-256-GCM, `HmacSHA256` for the RFC 5869 HKDF construction, and
 * [SecureRandom] for salt/nonce generation. It does not implement AES, SHA-256,
 * HMAC, GCM, HKDF internals, or RNG by hand, and it has no dependency on the
 * Android framework, Keystore, storage, networking, ratchets, or ML-KEM.
 */
sealed class SecureEnvelopeException(message: String) : Exception(message) {
    /** Structural decode failure: bad magic, truncation, trailing bytes, bad fixed length, or header mismatch. */
    class MalformedEnvelope : SecureEnvelopeException("Malformed secure envelope.")

    /** The version byte is not the supported v1. */
    class UnsupportedVersion(val version: Int) : SecureEnvelopeException("Unsupported secure envelope version: $version.")

    /** The suite identifier is not in the registry. */
    class UnsupportedSuite(val suite: Int) : SecureEnvelopeException("Unsupported secure envelope suite: $suite.")

    /** Input key material is shorter than the required minimum. */
    class InvalidKeyMaterial : SecureEnvelopeException("Invalid secure envelope key material.")

    /** Public metadata is empty (key identifier) or oversized. */
    class InvalidMetadata : SecureEnvelopeException("Invalid secure envelope metadata.")

    /** AEAD verification failed on open (wrong key, tampered header/ciphertext/tag). */
    class AuthenticationFailed : SecureEnvelopeException("Secure envelope authentication failed.")

    /** Secure randomness could not be produced. */
    class RandomnessUnavailable : SecureEnvelopeException("Secure randomness is unavailable.")

    /** The preview helper's maximum payload size was exceeded. */
    class PreviewPayloadTooLarge : SecureEnvelopeException("Secure envelope preview payload is too large.")
}

/** Supported algorithm suites. v1 defines exactly one. */
enum class SecureEnvelopeSuite(val id: Int) {
    V1_AES_256_GCM_HKDF_SHA256(0x0001);

    companion object {
        @JvmStatic
        fun fromId(id: Int): SecureEnvelopeSuite? = entries.firstOrNull { it.id == id }
    }
}

/**
 * Public, authenticated (not encrypted) envelope metadata.
 *
 * Treat both fields as routable public data; never place secrets in them.
 * Stored arrays are defensively copied; callers should not mutate the exposed
 * arrays.
 */
class SecureEnvelopeMetadata @JvmOverloads constructor(
    keyIdentifier: ByteArray,
    publicContext: ByteArray = ByteArray(0),
) {
    val keyIdentifier: ByteArray = keyIdentifier.copyOf()
    val publicContext: ByteArray = publicContext.copyOf()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SecureEnvelopeMetadata) return false
        return keyIdentifier.contentEquals(other.keyIdentifier) &&
            publicContext.contentEquals(other.publicContext)
    }

    override fun hashCode(): Int = 31 * keyIdentifier.contentHashCode() + publicContext.contentHashCode()
}

/**
 * An immutable parsed/sealed envelope. [serializedData] is the canonical wire
 * representation. Construct via [SecureEnvelopeSealer] or [parse].
 */
class SecureEnvelope private constructor(
    val version: Int,
    val suite: SecureEnvelopeSuite,
    val metadata: SecureEnvelopeMetadata,
    val salt: ByteArray,
    val nonce: ByteArray,
    val ciphertext: ByteArray,
    val tag: ByteArray,
    val serializedData: ByteArray,
    internal val authenticatedHeader: ByteArray,
) {
    companion object {
        /** Parse and strictly validate a serialized envelope. */
        @JvmStatic
        fun parse(serializedData: ByteArray): SecureEnvelope {
            val envelope = SecureEnvelopeWireFormat.decode(serializedData)
            if (!envelope.serializedData.contentEquals(serializedData)) {
                throw SecureEnvelopeException.MalformedEnvelope()
            }
            return envelope
        }

        internal fun build(
            version: Int,
            suite: SecureEnvelopeSuite,
            metadata: SecureEnvelopeMetadata,
            salt: ByteArray,
            nonce: ByteArray,
            ciphertext: ByteArray,
            tag: ByteArray,
        ): SecureEnvelope {
            SecureEnvelopeWireFormat.validateMetadata(metadata)
            if (version != SecureEnvelopeWireFormat.VERSION) {
                throw SecureEnvelopeException.UnsupportedVersion(version)
            }
            if (salt.size != SecureEnvelopeWireFormat.SALT_BYTE_COUNT ||
                nonce.size != SecureEnvelopeWireFormat.NONCE_BYTE_COUNT ||
                tag.size != SecureEnvelopeWireFormat.TAG_BYTE_COUNT
            ) {
                throw SecureEnvelopeException.MalformedEnvelope()
            }

            val header = SecureEnvelopeWireFormat.headerBytes(
                version = version,
                suite = suite,
                metadata = metadata,
                salt = salt,
                nonce = nonce,
                ciphertextByteCount = ciphertext.size,
                tagByteCount = tag.size,
            )
            val serialized = header + ciphertext + tag
            return SecureEnvelope(
                version = version,
                suite = suite,
                metadata = metadata,
                salt = salt.copyOf(),
                nonce = nonce.copyOf(),
                ciphertext = ciphertext.copyOf(),
                tag = tag.copyOf(),
                serializedData = serialized,
                authenticatedHeader = header,
            )
        }
    }
}

/** Seals plaintext into a [SecureEnvelope]. */
class SecureEnvelopeSealer internal constructor(
    private val randomBytes: (Int) -> ByteArray,
) {
    constructor() : this({ count -> SecureRandomBytes.generate(count) })

    fun seal(
        plaintext: ByteArray,
        keyMaterial: ByteArray,
        metadata: SecureEnvelopeMetadata,
    ): SecureEnvelope {
        val salt = randomBytes(SecureEnvelopeWireFormat.SALT_BYTE_COUNT)
        val nonce = randomBytes(SecureEnvelopeWireFormat.NONCE_BYTE_COUNT)
        return seal(plaintext, keyMaterial, metadata, salt, nonce)
    }

    internal fun seal(
        plaintext: ByteArray,
        keyMaterial: ByteArray,
        metadata: SecureEnvelopeMetadata,
        salt: ByteArray,
        nonce: ByteArray,
    ): SecureEnvelope {
        SecureEnvelopeCrypto.validateKeyMaterial(keyMaterial)
        SecureEnvelopeWireFormat.validateMetadata(metadata)
        if (salt.size != SecureEnvelopeWireFormat.SALT_BYTE_COUNT ||
            nonce.size != SecureEnvelopeWireFormat.NONCE_BYTE_COUNT
        ) {
            throw SecureEnvelopeException.MalformedEnvelope()
        }

        val header = SecureEnvelopeWireFormat.headerBytes(
            version = SecureEnvelopeWireFormat.VERSION,
            suite = SecureEnvelopeSuite.V1_AES_256_GCM_HKDF_SHA256,
            metadata = metadata,
            salt = salt,
            nonce = nonce,
            ciphertextByteCount = plaintext.size,
            tagByteCount = SecureEnvelopeWireFormat.TAG_BYTE_COUNT,
        )
        val key = SecureEnvelopeCrypto.deriveContentKey(
            keyMaterial = keyMaterial,
            salt = salt,
            suite = SecureEnvelopeSuite.V1_AES_256_GCM_HKDF_SHA256,
        )
        val sealed = SecureEnvelopeCrypto.seal(
            plaintext = plaintext,
            key = key,
            nonce = nonce,
            authenticatedData = header,
        )
        return SecureEnvelope.build(
            version = SecureEnvelopeWireFormat.VERSION,
            suite = SecureEnvelopeSuite.V1_AES_256_GCM_HKDF_SHA256,
            metadata = metadata,
            salt = salt,
            nonce = nonce,
            ciphertext = sealed.first,
            tag = sealed.second,
        )
    }
}

/** Opens a [SecureEnvelope] back to plaintext. */
class SecureEnvelopeOpener {
    fun open(serializedData: ByteArray, keyMaterial: ByteArray): ByteArray =
        open(SecureEnvelope.parse(serializedData), keyMaterial)

    fun open(envelope: SecureEnvelope, keyMaterial: ByteArray): ByteArray {
        SecureEnvelopeCrypto.validateKeyMaterial(keyMaterial)
        val key = SecureEnvelopeCrypto.deriveContentKey(
            keyMaterial = keyMaterial,
            salt = envelope.salt,
            suite = envelope.suite,
        )
        return SecureEnvelopeCrypto.open(
            ciphertext = envelope.ciphertext,
            tag = envelope.tag,
            key = key,
            nonce = envelope.nonce,
            authenticatedData = envelope.authenticatedHeader,
        )
    }
}

/** Caller-owned result returned by [SecureEnvelopePreview]. */
class SecureEnvelopePreviewResult internal constructor(
    val metadata: SecureEnvelopeMetadata,
    val plaintext: ByteArray,
)

/**
 * Preview-safe helper for small, caller-provided preview payloads. It parses
 * metadata, authenticates the deterministic header as AAD, decrypts a bounded
 * payload, and returns caller-owned display data. It has no storage, network,
 * sync, ratchet, ML-KEM, or notification-UI dependencies.
 */
class SecureEnvelopePreview @JvmOverloads constructor(
    val maxPlaintextBytes: Int = 4096,
) {
    fun open(serializedData: ByteArray, keyMaterial: ByteArray): SecureEnvelopePreviewResult {
        val envelope = SecureEnvelope.parse(serializedData)
        if (maxPlaintextBytes < 0 || envelope.ciphertext.size > maxPlaintextBytes) {
            throw SecureEnvelopeException.PreviewPayloadTooLarge()
        }
        val plaintext = SecureEnvelopeOpener().open(envelope, keyMaterial)
        if (plaintext.size > maxPlaintextBytes) {
            throw SecureEnvelopeException.PreviewPayloadTooLarge()
        }
        return SecureEnvelopePreviewResult(metadata = envelope.metadata, plaintext = plaintext)
    }
}

internal object SecureEnvelopeCrypto {
    const val MIN_KEY_MATERIAL_BYTE_COUNT = 32

    fun validateKeyMaterial(keyMaterial: ByteArray) {
        if (keyMaterial.size < MIN_KEY_MATERIAL_BYTE_COUNT) {
            throw SecureEnvelopeException.InvalidKeyMaterial()
        }
    }

    fun deriveContentKey(
        keyMaterial: ByteArray,
        salt: ByteArray,
        suite: SecureEnvelopeSuite,
    ): ByteArray {
        validateKeyMaterial(keyMaterial)
        if (salt.size != SecureEnvelopeWireFormat.SALT_BYTE_COUNT) {
            throw SecureEnvelopeException.MalformedEnvelope()
        }
        return Hkdf.deriveKey(
            inputKeyMaterial = keyMaterial,
            salt = salt,
            info = hkdfInfo(suite),
            outputByteCount = 32,
        )
    }

    fun seal(
        plaintext: ByteArray,
        key: ByteArray,
        nonce: ByteArray,
        authenticatedData: ByteArray,
    ): Pair<ByteArray, ByteArray> {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(SecureEnvelopeWireFormat.TAG_BYTE_COUNT * 8, nonce),
        )
        cipher.updateAAD(authenticatedData)
        val combined = cipher.doFinal(plaintext)
        val tagStart = combined.size - SecureEnvelopeWireFormat.TAG_BYTE_COUNT
        val ciphertext = combined.copyOfRange(0, tagStart)
        val tag = combined.copyOfRange(tagStart, combined.size)
        return ciphertext to tag
    }

    fun open(
        ciphertext: ByteArray,
        tag: ByteArray,
        key: ByteArray,
        nonce: ByteArray,
        authenticatedData: ByteArray,
    ): ByteArray {
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(key, "AES"),
                GCMParameterSpec(SecureEnvelopeWireFormat.TAG_BYTE_COUNT * 8, nonce),
            )
            cipher.updateAAD(authenticatedData)
            cipher.doFinal(ciphertext + tag)
        } catch (_: GeneralSecurityException) {
            throw SecureEnvelopeException.AuthenticationFailed()
        }
    }

    private fun hkdfInfo(suite: SecureEnvelopeSuite): ByteArray = when (suite) {
        SecureEnvelopeSuite.V1_AES_256_GCM_HKDF_SHA256 ->
            "SecureEnvelopeKit/v1/aes-256-gcm+hkdf-sha256".toByteArray(Charsets.UTF_8)
    }
}

/** RFC 5869 HKDF over a provider-backed HMAC-SHA-256. */
internal object Hkdf {
    fun deriveKey(
        inputKeyMaterial: ByteArray,
        salt: ByteArray,
        info: ByteArray,
        outputByteCount: Int,
    ): ByteArray {
        require(outputByteCount >= 0) { "outputByteCount must be non-negative" }
        val mac = Mac.getInstance("HmacSHA256")
        val hashLen = mac.macLength
        require(outputByteCount <= 255 * hashLen) { "outputByteCount too large for HKDF-SHA-256" }

        // Extract: PRK = HMAC(salt, IKM). RFC 5869 uses HashLen zero bytes when salt is empty.
        val effectiveSalt = if (salt.isEmpty()) ByteArray(hashLen) else salt
        mac.init(SecretKeySpec(effectiveSalt, "HmacSHA256"))
        val prk = mac.doFinal(inputKeyMaterial)

        // Expand: T(i) = HMAC(PRK, T(i-1) || info || i).
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        val okm = ByteArray(outputByteCount)
        var previousBlock = ByteArray(0)
        var position = 0
        var counter = 1
        while (position < outputByteCount) {
            mac.update(previousBlock)
            mac.update(info)
            mac.update(counter.toByte())
            previousBlock = mac.doFinal()
            val toCopy = minOf(previousBlock.size, outputByteCount - position)
            System.arraycopy(previousBlock, 0, okm, position, toCopy)
            position += toCopy
            counter++
        }
        return okm
    }
}

internal object SecureRandomBytes {
    private val random = SecureRandom()

    fun generate(count: Int): ByteArray {
        if (count < 0) throw SecureEnvelopeException.RandomnessUnavailable()
        if (count == 0) return ByteArray(0)
        val bytes = ByteArray(count)
        random.nextBytes(bytes)
        return bytes
    }
}

internal object SecureEnvelopeWireFormat {
    val MAGIC = byteArrayOf(0x53, 0x45, 0x4B) // "SEK"
    const val VERSION = 1
    const val SALT_BYTE_COUNT = 32
    const val NONCE_BYTE_COUNT = 12
    const val TAG_BYTE_COUNT = 16

    private const val U16_MAX = 0xFFFF
    private const val U32_MAX = 0xFFFFFFFFL

    fun validateMetadata(metadata: SecureEnvelopeMetadata) {
        if (metadata.keyIdentifier.isEmpty() || metadata.keyIdentifier.size > U16_MAX) {
            throw SecureEnvelopeException.InvalidMetadata()
        }
        if (metadata.publicContext.size.toLong() > U32_MAX) {
            throw SecureEnvelopeException.InvalidMetadata()
        }
    }

    fun headerBytes(
        version: Int,
        suite: SecureEnvelopeSuite,
        metadata: SecureEnvelopeMetadata,
        salt: ByteArray,
        nonce: ByteArray,
        ciphertextByteCount: Int,
        tagByteCount: Int,
    ): ByteArray {
        validateMetadata(metadata)
        if (ciphertextByteCount < 0 || ciphertextByteCount.toLong() > U32_MAX) {
            throw SecureEnvelopeException.MalformedEnvelope()
        }
        if (salt.size != SALT_BYTE_COUNT || nonce.size != NONCE_BYTE_COUNT || tagByteCount != TAG_BYTE_COUNT) {
            throw SecureEnvelopeException.MalformedEnvelope()
        }

        val out = ByteArrayOutputStream()
        out.write(MAGIC)
        out.writeU8(version)
        out.writeU16(suite.id)
        out.writeU16(metadata.keyIdentifier.size)
        out.write(metadata.keyIdentifier)
        out.writeU32(metadata.publicContext.size)
        out.write(metadata.publicContext)
        out.writeU8(salt.size)
        out.write(salt)
        out.writeU8(nonce.size)
        out.write(nonce)
        out.writeU32(ciphertextByteCount)
        out.writeU8(tagByteCount)
        return out.toByteArray()
    }

    fun decode(data: ByteArray): SecureEnvelope {
        val reader = ByteReader(data)

        val magic = reader.readBytes(MAGIC.size)
        if (!magic.contentEquals(MAGIC)) throw SecureEnvelopeException.MalformedEnvelope()

        val version = reader.readU8()
        if (version != VERSION) throw SecureEnvelopeException.UnsupportedVersion(version)

        val suiteId = reader.readU16()
        val suite = SecureEnvelopeSuite.fromId(suiteId)
            ?: throw SecureEnvelopeException.UnsupportedSuite(suiteId)

        val keyIdentifierLength = reader.readU16()
        if (keyIdentifierLength == 0) throw SecureEnvelopeException.MalformedEnvelope()
        val keyIdentifier = reader.readBytes(keyIdentifierLength)

        val publicContext = reader.readBytes(reader.readU32())

        val saltLength = reader.readU8()
        val salt = reader.readBytes(saltLength)
        if (salt.size != SALT_BYTE_COUNT) throw SecureEnvelopeException.MalformedEnvelope()

        val nonceLength = reader.readU8()
        val nonce = reader.readBytes(nonceLength)
        if (nonce.size != NONCE_BYTE_COUNT) throw SecureEnvelopeException.MalformedEnvelope()

        val ciphertextLength = reader.readU32()
        val tagLength = reader.readU8()
        if (tagLength != TAG_BYTE_COUNT) throw SecureEnvelopeException.MalformedEnvelope()

        val headerLength = reader.offset
        val ciphertext = reader.readBytes(ciphertextLength)
        val tag = reader.readBytes(tagLength)
        if (!reader.isAtEnd) throw SecureEnvelopeException.MalformedEnvelope()

        val metadata = SecureEnvelopeMetadata(keyIdentifier, publicContext)
        validateMetadata(metadata)

        val envelope = SecureEnvelope.build(version, suite, metadata, salt, nonce, ciphertext, tag)
        if (envelope.authenticatedHeader.size != headerLength) {
            throw SecureEnvelopeException.MalformedEnvelope()
        }
        return envelope
    }

    private fun ByteArrayOutputStream.writeU8(value: Int) {
        write(value and 0xFF)
    }

    private fun ByteArrayOutputStream.writeU16(value: Int) {
        write((value ushr 8) and 0xFF)
        write(value and 0xFF)
    }

    private fun ByteArrayOutputStream.writeU32(value: Int) {
        write((value ushr 24) and 0xFF)
        write((value ushr 16) and 0xFF)
        write((value ushr 8) and 0xFF)
        write(value and 0xFF)
    }
}

private class ByteReader(private val data: ByteArray) {
    var offset = 0
        private set

    val isAtEnd: Boolean get() = offset == data.size

    fun readU8(): Int = readBytes(1)[0].toInt() and 0xFF

    fun readU16(): Int {
        val bytes = readBytes(2)
        return ((bytes[0].toInt() and 0xFF) shl 8) or (bytes[1].toInt() and 0xFF)
    }

    fun readU32(): Long {
        val bytes = readBytes(4)
        var value = 0L
        for (byte in bytes) {
            value = (value shl 8) or (byte.toLong() and 0xFF)
        }
        return value
    }

    fun readBytes(count: Int): ByteArray = readBytes(count.toLong())

    fun readBytes(count: Long): ByteArray {
        if (count < 0 || count > (data.size - offset).toLong()) {
            throw SecureEnvelopeException.MalformedEnvelope()
        }
        val length = count.toInt()
        val result = data.copyOfRange(offset, offset + length)
        offset += length
        return result
    }
}
