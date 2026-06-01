package io.github.marlonjd.secureenvelope

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class HkdfTest {
    @Test
    fun hkdfMatchesRfc5869TestCase1() {
        // RFC 5869, Appendix A, Test Case 1 (HKDF-SHA-256).
        val ikm = ByteArray(22) { 0x0b }
        val salt = hexToBytes("000102030405060708090a0b0c")
        val info = hexToBytes("f0f1f2f3f4f5f6f7f8f9")
        val expectedOkm = hexToBytes(
            "3cb25f25faacd57a90434f64d0362f2a" +
                "2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
                "34007208d5b887185865",
        )

        val okm = Hkdf.deriveKey(ikm, salt, info, expectedOkm.size)

        assertArrayEquals(expectedOkm, okm)
    }

    @Test
    fun hkdfDerivationIsDeterministicAndSaltDependent() {
        val keyMaterial = ByteArray(32) { it.toByte() }
        val salt = ByteArray(32) { (it + 32).toByte() }
        val differentSalt = ByteArray(32) { (it + 33).toByte() }

        val first = SecureEnvelopeCrypto.deriveContentKey(
            keyMaterial, salt, SecureEnvelopeSuite.V1_AES_256_GCM_HKDF_SHA256,
        )
        val second = SecureEnvelopeCrypto.deriveContentKey(
            keyMaterial, salt, SecureEnvelopeSuite.V1_AES_256_GCM_HKDF_SHA256,
        )
        val other = SecureEnvelopeCrypto.deriveContentKey(
            keyMaterial, differentSalt, SecureEnvelopeSuite.V1_AES_256_GCM_HKDF_SHA256,
        )

        assertEquals(32, first.size)
        assertArrayEquals(first, second)
        assertFalse(first.contentEquals(other))
    }
}
