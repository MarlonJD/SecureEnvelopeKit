using System.Security.Cryptography;
using Xunit;

namespace SecureEnvelopeKit.Tests;

public class HkdfTests
{
    [Fact]
    public void BuiltInHkdfMatchesRfc5869TestCase1()
    {
        // RFC 5869, Appendix A, Test Case 1 (HKDF-SHA-256). DeriveContentKey relies
        // on this same built-in HKDF; this pins the primitive to the RFC vector.
        var ikm = Enumerable.Repeat((byte)0x0b, 22).ToArray();
        var salt = Convert.FromHexString("000102030405060708090a0b0c");
        var info = Convert.FromHexString("f0f1f2f3f4f5f6f7f8f9");
        var expected = Convert.FromHexString(
            "3cb25f25faacd57a90434f64d0362f2a" +
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
            "34007208d5b887185865");

        var okm = new byte[expected.Length];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, okm, salt, info);

        Assert.Equal(expected, okm);
    }

    [Fact]
    public void DerivationIsDeterministicAndSaltDependent()
    {
        var keyMaterial = Bytes(0, 32);
        var salt = Bytes(32, 32);
        var differentSalt = Bytes(33, 32);

        var first = SecureEnvelopeCrypto.DeriveContentKey(keyMaterial, salt, SecureEnvelopeSuite.V1Aes256GcmHkdfSha256);
        var second = SecureEnvelopeCrypto.DeriveContentKey(keyMaterial, salt, SecureEnvelopeSuite.V1Aes256GcmHkdfSha256);
        var other = SecureEnvelopeCrypto.DeriveContentKey(keyMaterial, differentSalt, SecureEnvelopeSuite.V1Aes256GcmHkdfSha256);

        Assert.Equal(32, first.Length);
        Assert.Equal(first, second);
        Assert.NotEqual(first, other);
    }

    private static byte[] Bytes(int start, int count)
    {
        var bytes = new byte[count];
        for (var i = 0; i < count; i++)
        {
            bytes[i] = (byte)(start + i);
        }
        return bytes;
    }
}
