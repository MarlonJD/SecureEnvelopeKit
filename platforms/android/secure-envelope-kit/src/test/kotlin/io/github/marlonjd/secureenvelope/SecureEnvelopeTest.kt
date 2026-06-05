package io.github.marlonjd.secureenvelope

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class SecureEnvelopeTest {
    private val keyMaterial = ByteArray(32) { it.toByte() }
    private val wrongKeyMaterial = ByteArray(32) { (it + 64).toByte() }
    private val salt = ByteArray(32) { (it + 32).toByte() }
    private val nonce = ByteArray(12) { (it + 96).toByte() }
    private val metadata = SecureEnvelopeMetadata(
        keyIdentifier = "key-1".toByteArray(Charsets.UTF_8),
        publicContext = "preview".toByteArray(Charsets.UTF_8),
    )
    private val plaintext = "hello secure envelope".toByteArray(Charsets.UTF_8)

    private fun deterministicEnvelope(): SecureEnvelope =
        SecureEnvelopeSealer().seal(plaintext, keyMaterial, metadata, salt, nonce)

    @Test
    fun sealAndOpenRoundTrip() {
        val envelope = deterministicEnvelope()

        val opened = SecureEnvelopeOpener().open(envelope, keyMaterial)

        assertArrayEquals(plaintext, opened)
        assertEquals(1, envelope.version)
        assertEquals(SecureEnvelopeSuite.V1_AES_256_GCM_HKDF_SHA256, envelope.suite)
        assertEquals(metadata, envelope.metadata)
    }

    @Test
    fun publicByteArrayViewsAreDefensiveCopies() {
        val metadata = SecureEnvelopeMetadata(
            keyIdentifier = "key-1".toByteArray(Charsets.UTF_8),
            publicContext = "preview".toByteArray(Charsets.UTF_8),
        )
        val exposedKeyIdentifier = metadata.keyIdentifier
        val exposedPublicContext = metadata.publicContext
        exposedKeyIdentifier[0] = 'X'.code.toByte()
        exposedPublicContext[0] = 'Y'.code.toByte()
        assertArrayEquals("key-1".toByteArray(Charsets.UTF_8), metadata.keyIdentifier)
        assertArrayEquals("preview".toByteArray(Charsets.UTF_8), metadata.publicContext)

        val envelope = deterministicEnvelope()
        val expectedSerialized = envelope.serializedData.copyOf()
        val expectedSalt = envelope.salt.copyOf()
        val expectedNonce = envelope.nonce.copyOf()
        val expectedCiphertext = envelope.ciphertext.copyOf()
        val expectedTag = envelope.tag.copyOf()
        val expectedHeader = envelope.authenticatedHeader.copyOf()

        envelope.serializedData[0] = 0
        envelope.salt[0] = 0
        envelope.nonce[0] = 0
        envelope.ciphertext[0] = 0
        envelope.tag[0] = 0
        envelope.authenticatedHeader[0] = 0

        assertArrayEquals(expectedSerialized, envelope.serializedData)
        assertArrayEquals(expectedSalt, envelope.salt)
        assertArrayEquals(expectedNonce, envelope.nonce)
        assertArrayEquals(expectedCiphertext, envelope.ciphertext)
        assertArrayEquals(expectedTag, envelope.tag)
        assertArrayEquals(expectedHeader, envelope.authenticatedHeader)
        assertArrayEquals(plaintext, SecureEnvelopeOpener().open(envelope, keyMaterial))

        val previewResult = SecureEnvelopePreview(maxPlaintextBytes = 64).open(
            envelope.serializedData,
            keyMaterial,
        )
        val expectedPreview = previewResult.plaintext.copyOf()
        previewResult.plaintext[0] = 0
        assertArrayEquals(expectedPreview, previewResult.plaintext)
    }

    @Test
    fun openWithWrongKeyFailsAuthentication() {
        val envelope = deterministicEnvelope()

        assertEnvelopeError<SecureEnvelopeException.AuthenticationFailed> {
            SecureEnvelopeOpener().open(envelope, wrongKeyMaterial)
        }
    }

    @Test
    fun tamperedHeaderFailsAuthentication() {
        val envelope = deterministicEnvelope()
        val tampered = envelope.serializedData.copyOf()
        val firstKeyIdentifierByteOffset = 8
        tampered[firstKeyIdentifierByteOffset] = (tampered[firstKeyIdentifierByteOffset].toInt() xor 0x01).toByte()

        val parsed = SecureEnvelope.parse(tampered)
        assertEnvelopeError<SecureEnvelopeException.AuthenticationFailed> {
            SecureEnvelopeOpener().open(parsed, keyMaterial)
        }
    }

    @Test
    fun tamperedCiphertextFailsAuthentication() {
        val envelope = deterministicEnvelope()
        val tampered = envelope.serializedData.copyOf()
        val offset = envelope.authenticatedHeader.size
        tampered[offset] = (tampered[offset].toInt() xor 0x01).toByte()

        val parsed = SecureEnvelope.parse(tampered)
        assertEnvelopeError<SecureEnvelopeException.AuthenticationFailed> {
            SecureEnvelopeOpener().open(parsed, keyMaterial)
        }
    }

    @Test
    fun tamperedTagFailsAuthentication() {
        val envelope = deterministicEnvelope()
        val tampered = envelope.serializedData.copyOf()
        val last = tampered.size - 1
        tampered[last] = (tampered[last].toInt() xor 0x01).toByte()

        val parsed = SecureEnvelope.parse(tampered)
        assertEnvelopeError<SecureEnvelopeException.AuthenticationFailed> {
            SecureEnvelopeOpener().open(parsed, keyMaterial)
        }
    }

    @Test
    fun malformedEnvelopeDecodeFailures() {
        val envelope = deterministicEnvelope()

        // Truncation.
        assertEnvelopeError<SecureEnvelopeException.MalformedEnvelope> {
            SecureEnvelope.parse(envelope.serializedData.copyOf(envelope.serializedData.size - 1))
        }

        // Trailing bytes.
        assertEnvelopeError<SecureEnvelopeException.MalformedEnvelope> {
            SecureEnvelope.parse(envelope.serializedData + byteArrayOf(0xFF.toByte()))
        }

        // Unsupported version.
        val unsupportedVersion = envelope.serializedData.copyOf()
        unsupportedVersion[3] = 2
        val versionError = assertEnvelopeError<SecureEnvelopeException.UnsupportedVersion> {
            SecureEnvelope.parse(unsupportedVersion)
        }
        assertEquals(2, versionError.version)

        // Unsupported suite (0x7fff).
        val unsupportedSuite = envelope.serializedData.copyOf()
        unsupportedSuite[4] = 0x7f
        unsupportedSuite[5] = 0xFF.toByte()
        val suiteError = assertEnvelopeError<SecureEnvelopeException.UnsupportedSuite> {
            SecureEnvelope.parse(unsupportedSuite)
        }
        assertEquals(0x7fff, suiteError.suite)
    }

    @Test
    fun stableBinaryEncodingRoundTrips() {
        val envelope = deterministicEnvelope()

        val reparsed = SecureEnvelope.parse(envelope.serializedData)
        assertArrayEquals(envelope.serializedData, reparsed.serializedData)
        assertArrayEquals(envelope.authenticatedHeader, reparsed.authenticatedHeader)
        assertEquals(envelope.metadata, reparsed.metadata)
        assertArrayEquals(envelope.ciphertext, reparsed.ciphertext)
        assertArrayEquals(envelope.tag, reparsed.tag)
    }

    @Test
    fun previewHelperReturnsCallerOwnedPreviewData() {
        val envelope = deterministicEnvelope()
        val preview = SecureEnvelopePreview(maxPlaintextBytes = 64)

        val result = preview.open(envelope.serializedData, keyMaterial)

        assertEquals(metadata, result.metadata)
        assertArrayEquals(plaintext, result.plaintext)
    }

    @Test
    fun previewHelperRejectsOversizedPayloadBeforeOpen() {
        val envelope = deterministicEnvelope()
        val preview = SecureEnvelopePreview(maxPlaintextBytes = 4)

        assertEnvelopeError<SecureEnvelopeException.PreviewPayloadTooLarge> {
            preview.open(envelope.serializedData, keyMaterial)
        }
    }

    @Test
    fun previewHelperRejectsOversizedSerializedEnvelopeBeforeParse() {
        val envelope = deterministicEnvelope()
        val preview = SecureEnvelopePreview(
            maxPlaintextBytes = 64,
            maxSerializedEnvelopeBytes = envelope.serializedData.size - 1,
        )

        assertEnvelopeError<SecureEnvelopeException.PreviewPayloadTooLarge> {
            preview.open(envelope.serializedData, wrongKeyMaterial)
        }
    }

    @Test
    fun previewHelperRejectsOversizedPublicMetadataBeforeOpen() {
        val envelope = deterministicEnvelope()
        val preview = SecureEnvelopePreview(
            maxPlaintextBytes = 64,
            maxSerializedEnvelopeBytes = 4096,
            maxPublicMetadataBytes = 4,
        )

        assertEnvelopeError<SecureEnvelopeException.PreviewPayloadTooLarge> {
            preview.open(envelope.serializedData, wrongKeyMaterial)
        }
    }

    @Test
    fun invalidInputsAreRejected() {
        assertEnvelopeError<SecureEnvelopeException.InvalidKeyMaterial> {
            SecureEnvelopeSealer().seal(
                plaintext,
                "too-short".toByteArray(Charsets.UTF_8),
                metadata,
                salt,
                nonce,
            )
        }

        assertEnvelopeError<SecureEnvelopeException.InvalidMetadata> {
            SecureEnvelopeSealer().seal(
                plaintext,
                keyMaterial,
                SecureEnvelopeMetadata(keyIdentifier = ByteArray(0)),
                salt,
                nonce,
            )
        }
    }

    @Test
    fun sealerGeneratesFreshSaltAndNoncePerEnvelope() {
        val sealer = SecureEnvelopeSealer()

        val first = sealer.seal(plaintext, keyMaterial, metadata)
        val second = sealer.seal(plaintext, keyMaterial, metadata)

        assertEquals(SecureEnvelopeWireFormat.SALT_BYTE_COUNT, first.salt.size)
        assertEquals(SecureEnvelopeWireFormat.NONCE_BYTE_COUNT, first.nonce.size)
        // Random salt/nonce make two seals of identical input differ.
        assert(!first.serializedData.contentEquals(second.serializedData))
        // Both still open to the original plaintext.
        assertArrayEquals(plaintext, SecureEnvelopeOpener().open(first, keyMaterial))
        assertArrayEquals(plaintext, SecureEnvelopeOpener().open(second, keyMaterial))
    }
}
