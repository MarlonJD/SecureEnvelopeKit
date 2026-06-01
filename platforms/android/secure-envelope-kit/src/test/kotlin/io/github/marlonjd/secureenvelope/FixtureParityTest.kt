package io.github.marlonjd.secureenvelope

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Cross-platform parity against the shared v1 fixture produced by the Swift
 * implementation. Reproducing the bytes proves the encrypt direction matches
 * (Kotlin -> Swift); opening the committed bytes proves the decrypt direction
 * matches (Swift -> Kotlin).
 */
class FixtureParityTest {
    @Test
    fun reproducesAndOpensSharedSwiftFixture() {
        val fixture = SecureEnvelopeV1Fixture.load()

        assertEquals(1, fixture.int("fixtureVersion"))
        assertEquals("stable", fixture.str("status"))
        assertEquals("secure-envelope-v1-aes-256-gcm-hkdf-sha256", fixture.str("name"))
        assertEquals(1, fixture.int("version"))
        assertEquals("0001", fixture.str("suiteIdHex"))
        assertEquals(
            "SecureEnvelopeKit/v1/aes-256-gcm+hkdf-sha256",
            fixture.str("hkdfInfoUtf8"),
        )

        val keyMaterial = fixture.hex("keyMaterialHex")
        val salt = fixture.hex("saltHex")
        val nonce = fixture.hex("nonceHex")
        val metadata = SecureEnvelopeMetadata(
            keyIdentifier = fixture.hex("keyIdentifierHex"),
            publicContext = fixture.hex("publicContextHex"),
        )
        val plaintext = fixture.hex("plaintextHex")

        // Content-key derivation parity.
        val derived = SecureEnvelopeCrypto.deriveContentKey(
            keyMaterial, salt, SecureEnvelopeSuite.V1_AES_256_GCM_HKDF_SHA256,
        )
        assertEquals(fixture.str("derivedContentKeyHex"), bytesToHex(derived))

        // Encrypt direction: reproduce the exact bytes from the fixture inputs.
        val envelope = SecureEnvelopeSealer().seal(plaintext, keyMaterial, metadata, salt, nonce)
        assertEquals(fixture.str("authenticatedHeaderHex"), bytesToHex(envelope.authenticatedHeader))
        assertEquals(fixture.str("ciphertextHex"), bytesToHex(envelope.ciphertext))
        assertEquals(fixture.str("tagHex"), bytesToHex(envelope.tag))
        assertEquals(fixture.str("envelopeHex"), bytesToHex(envelope.serializedData))

        // Decrypt direction: open the committed Swift envelope bytes.
        val committed = fixture.hex("envelopeHex")
        val opened = SecureEnvelopeOpener().open(committed, keyMaterial)
        assertArrayEquals(plaintext, opened)

        // Tampering the committed envelope fails authentication, like every platform.
        val tampered = committed.copyOf()
        val last = tampered.size - 1
        tampered[last] = (tampered[last].toInt() xor 0x01).toByte()
        assertEnvelopeError<SecureEnvelopeException.AuthenticationFailed> {
            SecureEnvelopeOpener().open(tampered, keyMaterial)
        }
    }
}
