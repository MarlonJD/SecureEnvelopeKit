using Xunit;
using static SecureEnvelopeKit.Tests.TestSupport;

namespace SecureEnvelopeKit.Tests;

public class SecureEnvelopeTests
{
    private static readonly byte[] KeyMaterial = CreateBytes(0, 32);
    private static readonly byte[] WrongKeyMaterial = CreateBytes(64, 32);
    private static readonly byte[] Salt = CreateBytes(32, 32);
    private static readonly byte[] Nonce = CreateBytes(96, 12);
    private static readonly SecureEnvelopeMetadata Metadata = new(
        "key-1"u8, "preview"u8);
    private static readonly byte[] Plaintext = "hello secure envelope"u8.ToArray();

    private static byte[] CreateBytes(int start, int count)
    {
        var bytes = new byte[count];
        for (var i = 0; i < count; i++)
        {
            bytes[i] = (byte)(start + i);
        }
        return bytes;
    }

    private static SecureEnvelope DeterministicEnvelope() =>
        new SecureEnvelopeSealer().Seal(Plaintext, KeyMaterial, Metadata, Salt, Nonce);

    [Fact]
    public void SealAndOpenRoundTrip()
    {
        var envelope = DeterministicEnvelope();

        var opened = new SecureEnvelopeOpener().Open(envelope, KeyMaterial);

        Assert.Equal(Plaintext, opened);
        Assert.Equal(1, envelope.Version);
        Assert.Equal(SecureEnvelopeSuite.V1Aes256GcmHkdfSha256, envelope.Suite);
        Assert.Equal(Metadata, envelope.Metadata);
    }

    [Fact]
    public void OpenWithWrongKeyFailsAuthentication()
    {
        var envelope = DeterministicEnvelope();

        AssertEnvelopeError(SecureEnvelopeError.AuthenticationFailed, () =>
            new SecureEnvelopeOpener().Open(envelope, WrongKeyMaterial));
    }

    [Fact]
    public void TamperedHeaderFailsAuthentication()
    {
        var envelope = DeterministicEnvelope();
        var tampered = envelope.SerializedData.ToArray();
        const int firstKeyIdentifierByteOffset = 8;
        tampered[firstKeyIdentifierByteOffset] ^= 0x01;

        var parsed = SecureEnvelope.Parse(tampered);
        AssertEnvelopeError(SecureEnvelopeError.AuthenticationFailed, () =>
            new SecureEnvelopeOpener().Open(parsed, KeyMaterial));
    }

    [Fact]
    public void TamperedCiphertextFailsAuthentication()
    {
        var envelope = DeterministicEnvelope();
        var tampered = envelope.SerializedData.ToArray();
        tampered[envelope.AuthenticatedHeader.Length] ^= 0x01;

        var parsed = SecureEnvelope.Parse(tampered);
        AssertEnvelopeError(SecureEnvelopeError.AuthenticationFailed, () =>
            new SecureEnvelopeOpener().Open(parsed, KeyMaterial));
    }

    [Fact]
    public void TamperedTagFailsAuthentication()
    {
        var envelope = DeterministicEnvelope();
        var tampered = envelope.SerializedData.ToArray();
        tampered[^1] ^= 0x01;

        var parsed = SecureEnvelope.Parse(tampered);
        AssertEnvelopeError(SecureEnvelopeError.AuthenticationFailed, () =>
            new SecureEnvelopeOpener().Open(parsed, KeyMaterial));
    }

    [Fact]
    public void MalformedEnvelopeDecodeFailures()
    {
        var envelope = DeterministicEnvelope();
        var serialized = envelope.SerializedData.ToArray();

        // Truncation.
        AssertEnvelopeError(SecureEnvelopeError.MalformedEnvelope, () =>
            SecureEnvelope.Parse(serialized.AsSpan(0, serialized.Length - 1)));

        // Trailing bytes.
        var trailing = new byte[serialized.Length + 1];
        serialized.CopyTo(trailing, 0);
        trailing[^1] = 0xFF;
        AssertEnvelopeError(SecureEnvelopeError.MalformedEnvelope, () =>
            SecureEnvelope.Parse(trailing));

        // Unsupported version.
        var unsupportedVersion = (byte[])serialized.Clone();
        unsupportedVersion[3] = 2;
        var versionError = AssertEnvelopeError(SecureEnvelopeError.UnsupportedVersion, () =>
            SecureEnvelope.Parse(unsupportedVersion));
        Assert.Equal(2, versionError.Code);

        // Unsupported suite (0x7fff).
        var unsupportedSuite = (byte[])serialized.Clone();
        unsupportedSuite[4] = 0x7f;
        unsupportedSuite[5] = 0xFF;
        var suiteError = AssertEnvelopeError(SecureEnvelopeError.UnsupportedSuite, () =>
            SecureEnvelope.Parse(unsupportedSuite));
        Assert.Equal(0x7fff, suiteError.Code);
    }

    [Fact]
    public void StableBinaryEncodingRoundTrips()
    {
        var envelope = DeterministicEnvelope();

        var reparsed = SecureEnvelope.Parse(envelope.SerializedData.Span);

        Assert.Equal(envelope.SerializedData.ToArray(), reparsed.SerializedData.ToArray());
        Assert.Equal(envelope.Metadata, reparsed.Metadata);
        Assert.Equal(envelope.Ciphertext.ToArray(), reparsed.Ciphertext.ToArray());
        Assert.Equal(envelope.Tag.ToArray(), reparsed.Tag.ToArray());
    }

    [Fact]
    public void PreviewHelperReturnsCallerOwnedPreviewData()
    {
        var envelope = DeterministicEnvelope();
        var preview = new SecureEnvelopePreview(maxPlaintextBytes: 64);

        var result = preview.Open(envelope.SerializedData.Span, KeyMaterial);

        Assert.Equal(Metadata, result.Metadata);
        Assert.Equal(Plaintext, result.Plaintext.ToArray());
    }

    [Fact]
    public void PreviewHelperRejectsOversizedPayloadBeforeOpen()
    {
        var envelope = DeterministicEnvelope();
        var preview = new SecureEnvelopePreview(maxPlaintextBytes: 4);

        AssertEnvelopeError(SecureEnvelopeError.PreviewPayloadTooLarge, () =>
            preview.Open(envelope.SerializedData.Span, KeyMaterial));
    }

    [Fact]
    public void InvalidInputsAreRejected()
    {
        AssertEnvelopeError(SecureEnvelopeError.InvalidKeyMaterial, () =>
            new SecureEnvelopeSealer().Seal(Plaintext, "too-short"u8, Metadata, Salt, Nonce));

        AssertEnvelopeError(SecureEnvelopeError.InvalidMetadata, () =>
            new SecureEnvelopeSealer().Seal(Plaintext, KeyMaterial, new SecureEnvelopeMetadata(default), Salt, Nonce));
    }

    [Fact]
    public void SealerGeneratesFreshSaltAndNoncePerEnvelope()
    {
        var sealer = new SecureEnvelopeSealer();

        var first = sealer.Seal(Plaintext, KeyMaterial, Metadata);
        var second = sealer.Seal(Plaintext, KeyMaterial, Metadata);

        Assert.Equal(32, first.Salt.Length);
        Assert.Equal(12, first.Nonce.Length);
        Assert.False(first.SerializedData.ToArray().AsSpan().SequenceEqual(second.SerializedData.ToArray()));
        Assert.Equal(Plaintext, new SecureEnvelopeOpener().Open(first, KeyMaterial));
        Assert.Equal(Plaintext, new SecureEnvelopeOpener().Open(second, KeyMaterial));
    }
}
