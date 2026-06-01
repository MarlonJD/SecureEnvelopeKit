using Xunit;
using static SecureEnvelopeKit.Tests.TestSupport;

namespace SecureEnvelopeKit.Tests;

/// <summary>
/// Cross-platform parity against the shared v1 fixture produced by the Swift
/// implementation. Reproducing the bytes proves the encrypt direction matches
/// (.NET -> Swift); opening the committed bytes proves the decrypt direction
/// matches (Swift -> .NET).
/// </summary>
public class FixtureParityTests
{
    [Fact]
    public void ReproducesAndOpensSharedSwiftFixture()
    {
        var fixture = SecureEnvelopeV1Fixture.Load();

        Assert.Equal(1, fixture.Int("fixtureVersion"));
        Assert.Equal("stable", fixture.Str("status"));
        Assert.Equal("secure-envelope-v1-aes-256-gcm-hkdf-sha256", fixture.Str("name"));
        Assert.Equal(1, fixture.Int("version"));
        Assert.Equal("0001", fixture.Str("suiteIdHex"));
        Assert.Equal("SecureEnvelopeKit/v1/aes-256-gcm+hkdf-sha256", fixture.Str("hkdfInfoUtf8"));

        var keyMaterial = fixture.Hex("keyMaterialHex");
        var salt = fixture.Hex("saltHex");
        var nonce = fixture.Hex("nonceHex");
        var metadata = new SecureEnvelopeMetadata(fixture.Hex("keyIdentifierHex"), fixture.Hex("publicContextHex"));
        var plaintext = fixture.Hex("plaintextHex");

        // Content-key derivation parity.
        var derived = SecureEnvelopeCrypto.DeriveContentKey(keyMaterial, salt, SecureEnvelopeSuite.V1Aes256GcmHkdfSha256);
        Assert.Equal(fixture.Str("derivedContentKeyHex"), Convert.ToHexString(derived).ToLowerInvariant());

        // Encrypt direction: reproduce the exact bytes from the fixture inputs.
        var envelope = new SecureEnvelopeSealer().Seal(plaintext, keyMaterial, metadata, salt, nonce);
        Assert.Equal(fixture.Str("authenticatedHeaderHex"), Convert.ToHexString(envelope.AuthenticatedHeader).ToLowerInvariant());
        Assert.Equal(fixture.Str("ciphertextHex"), ToHex(envelope.Ciphertext));
        Assert.Equal(fixture.Str("tagHex"), ToHex(envelope.Tag));
        Assert.Equal(fixture.Str("envelopeHex"), ToHex(envelope.SerializedData));

        // Decrypt direction: open the committed Swift envelope bytes.
        var committed = fixture.Hex("envelopeHex");
        var opened = new SecureEnvelopeOpener().Open(committed, keyMaterial);
        Assert.Equal(plaintext, opened);

        // Tampering the committed envelope fails authentication, like every platform.
        var tampered = (byte[])committed.Clone();
        tampered[^1] ^= 0x01;
        AssertEnvelopeError(SecureEnvelopeError.AuthenticationFailed, () =>
            new SecureEnvelopeOpener().Open(tampered, keyMaterial));
    }
}
