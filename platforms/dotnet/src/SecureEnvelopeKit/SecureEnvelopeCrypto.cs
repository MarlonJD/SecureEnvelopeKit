using System.Security.Cryptography;
using System.Text;

namespace SecureEnvelopeKit;

/// <summary>
/// Provider-backed crypto for the v1 suite. Uses only BCL primitives:
/// <see cref="AesGcm"/> for AES-256-GCM, the built-in <see cref="HKDF"/> for
/// HKDF-SHA-256, and <see cref="RandomNumberGenerator"/> for randomness. It does
/// not implement AES, SHA-256, HMAC, GCM, HKDF, or RNG by hand.
/// </summary>
internal static class SecureEnvelopeCrypto
{
    internal const int MinKeyMaterialByteCount = 32;

    internal static void ValidateKeyMaterial(ReadOnlySpan<byte> keyMaterial)
    {
        if (keyMaterial.Length < MinKeyMaterialByteCount)
        {
            throw SecureEnvelopeException.InvalidKeyMaterial();
        }
    }

    internal static byte[] DeriveContentKey(ReadOnlySpan<byte> keyMaterial, ReadOnlySpan<byte> salt, SecureEnvelopeSuite suite)
    {
        ValidateKeyMaterial(keyMaterial);
        if (salt.Length != SecureEnvelopeWireFormat.SaltByteCount)
        {
            throw SecureEnvelopeException.Malformed();
        }

        var key = new byte[32];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, keyMaterial, key, salt, HkdfInfo(suite));
        return key;
    }

    internal static (byte[] Ciphertext, byte[] Tag) Seal(
        ReadOnlySpan<byte> plaintext,
        byte[] key,
        byte[] nonce,
        ReadOnlySpan<byte> authenticatedData)
    {
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[SecureEnvelopeWireFormat.TagByteCount];
        using var aesGcm = new AesGcm(key, SecureEnvelopeWireFormat.TagByteCount);
        aesGcm.Encrypt(nonce, plaintext, ciphertext, tag, authenticatedData);
        return (ciphertext, tag);
    }

    internal static byte[] Open(
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        byte[] key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> authenticatedData)
    {
        var plaintext = new byte[ciphertext.Length];
        try
        {
            using var aesGcm = new AesGcm(key, SecureEnvelopeWireFormat.TagByteCount);
            aesGcm.Decrypt(nonce, ciphertext, tag, plaintext, authenticatedData);
        }
        catch (CryptographicException)
        {
            // AuthenticationTagMismatchException derives from CryptographicException.
            // Map every verification failure to one opaque outcome; return no plaintext.
            throw SecureEnvelopeException.AuthenticationFailed();
        }

        return plaintext;
    }

    private static byte[] HkdfInfo(SecureEnvelopeSuite suite) => suite switch
    {
        SecureEnvelopeSuite.V1Aes256GcmHkdfSha256 =>
            Encoding.UTF8.GetBytes("SecureEnvelopeKit/v1/aes-256-gcm+hkdf-sha256"),
        _ => throw SecureEnvelopeException.UnsupportedSuite((int)suite),
    };
}

internal static class SecureRandomBytes
{
    internal static byte[] Generate(int count)
    {
        if (count < 0)
        {
            throw SecureEnvelopeException.RandomnessUnavailable();
        }
        if (count == 0)
        {
            return [];
        }

        var bytes = new byte[count];
        RandomNumberGenerator.Fill(bytes);
        return bytes;
    }
}
