package io.github.marlonjd.secureenvelope

import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import java.io.File

internal fun hexToBytes(hex: String): ByteArray {
    require(hex.length % 2 == 0) { "hex string must have an even length" }
    return ByteArray(hex.length / 2) { index ->
        val hi = Character.digit(hex[index * 2], 16)
        val lo = Character.digit(hex[index * 2 + 1], 16)
        require(hi >= 0 && lo >= 0) { "invalid hex character in '$hex'" }
        ((hi shl 4) or lo).toByte()
    }
}

internal fun bytesToHex(bytes: ByteArray): String {
    val builder = StringBuilder(bytes.size * 2)
    for (byte in bytes) {
        builder.append("0123456789abcdef"[(byte.toInt() ushr 4) and 0xF])
        builder.append("0123456789abcdef"[byte.toInt() and 0xF])
    }
    return builder.toString()
}

/** Asserts [block] throws a [SecureEnvelopeException] of the expected subtype and returns it. */
internal inline fun <reified T : SecureEnvelopeException> assertEnvelopeError(block: () -> Unit): T {
    val thrown: SecureEnvelopeException? = try {
        block()
        null
    } catch (error: SecureEnvelopeException) {
        error
    }
    assertNotNull("expected ${T::class.simpleName} to be thrown", thrown)
    assertTrue(
        "expected ${T::class.simpleName} but got ${thrown!!::class.simpleName}",
        thrown is T,
    )
    return thrown as T
}

/**
 * Loads the shared cross-platform fixture from the repository-root `fixtures/`
 * directory. The path is provided by the `secureEnvelopeFixturesDir` system
 * property (wired up in the module's build.gradle.kts). The fixture is a flat
 * JSON object of string and number values, parsed here without a JSON
 * dependency to keep the unit-test classpath minimal.
 */
internal class SecureEnvelopeV1Fixture private constructor(private val fields: Map<String, String>) {
    fun str(key: String): String = fields[key] ?: error("missing fixture field: $key")
    fun int(key: String): Int = str(key).toInt()
    fun hex(key: String): ByteArray = hexToBytes(str(key))

    companion object {
        fun load(): SecureEnvelopeV1Fixture {
            val dir = System.getProperty("secureEnvelopeFixturesDir")
                ?: error("secureEnvelopeFixturesDir system property is not set")
            val file = File(dir, "SecureEnvelopeV1/secure-envelope-v1.json")
            require(file.exists()) { "shared fixture not found at ${file.absolutePath}" }
            val text = file.readText()
            val strings = Regex(""""([A-Za-z0-9_]+)"\s*:\s*"([^"]*)"""")
                .findAll(text)
                .associate { it.groupValues[1] to it.groupValues[2] }
            val numbers = Regex(""""([A-Za-z0-9_]+)"\s*:\s*(-?\d+)\s*[,}]""")
                .findAll(text)
                .associate { it.groupValues[1] to it.groupValues[2] }
            return SecureEnvelopeV1Fixture(numbers + strings)
        }
    }
}
