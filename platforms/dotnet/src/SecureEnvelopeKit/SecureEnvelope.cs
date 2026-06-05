namespace SecureEnvelopeKit;

/// <summary>Logical error cases surfaced by the secure envelope API.</summary>
public enum SecureEnvelopeError
{
    /// <summary>Structural decode failure (bad magic, truncation, trailing bytes, bad fixed length, header mismatch).</summary>
    MalformedEnvelope,

    /// <summary>The version byte is not the supported v1.</summary>
    UnsupportedVersion,

    /// <summary>The suite identifier is not in the registry.</summary>
    UnsupportedSuite,

    /// <summary>Input key material is shorter than the required minimum.</summary>
    InvalidKeyMaterial,

    /// <summary>Public metadata is empty (key identifier) or oversized.</summary>
    InvalidMetadata,

    /// <summary>AEAD verification failed on open (wrong key, tampered header/ciphertext/tag).</summary>
    AuthenticationFailed,

    /// <summary>Secure randomness could not be produced.</summary>
    RandomnessUnavailable,

    /// <summary>The preview helper's maximum payload size was exceeded.</summary>
    PreviewPayloadTooLarge,
}

/// <summary>The single exception type raised by SecureEnvelopeKit.</summary>
public sealed class SecureEnvelopeException : Exception
{
    /// <summary>The logical error case.</summary>
    public SecureEnvelopeError Error { get; }

    /// <summary>The offending version or suite value, when applicable.</summary>
    public int? Code { get; }

    internal SecureEnvelopeException(SecureEnvelopeError error, string message, int? code = null)
        : base(message)
    {
        Error = error;
        Code = code;
    }

    internal static SecureEnvelopeException Malformed() =>
        new(SecureEnvelopeError.MalformedEnvelope, "Malformed secure envelope.");

    internal static SecureEnvelopeException UnsupportedVersion(int version) =>
        new(SecureEnvelopeError.UnsupportedVersion, $"Unsupported secure envelope version: {version}.", version);

    internal static SecureEnvelopeException UnsupportedSuite(int suite) =>
        new(SecureEnvelopeError.UnsupportedSuite, $"Unsupported secure envelope suite: {suite}.", suite);

    internal static SecureEnvelopeException InvalidKeyMaterial() =>
        new(SecureEnvelopeError.InvalidKeyMaterial, "Invalid secure envelope key material.");

    internal static SecureEnvelopeException InvalidMetadata() =>
        new(SecureEnvelopeError.InvalidMetadata, "Invalid secure envelope metadata.");

    internal static SecureEnvelopeException AuthenticationFailed() =>
        new(SecureEnvelopeError.AuthenticationFailed, "Secure envelope authentication failed.");

    internal static SecureEnvelopeException RandomnessUnavailable() =>
        new(SecureEnvelopeError.RandomnessUnavailable, "Secure randomness is unavailable.");

    internal static SecureEnvelopeException PreviewPayloadTooLarge() =>
        new(SecureEnvelopeError.PreviewPayloadTooLarge, "Secure envelope preview payload is too large.");
}

/// <summary>Supported algorithm suites. v1 defines exactly one.</summary>
public enum SecureEnvelopeSuite : ushort
{
    /// <summary>AES-256-GCM with an HKDF-SHA-256 content key.</summary>
    V1Aes256GcmHkdfSha256 = 0x0001,
}

/// <summary>
/// Public, authenticated (not encrypted) envelope metadata. Treat both fields
/// as routable public data; never place secrets in them. Stored bytes are
/// defensively copied.
/// </summary>
public sealed class SecureEnvelopeMetadata : IEquatable<SecureEnvelopeMetadata>
{
    private readonly byte[] _keyIdentifier;
    private readonly byte[] _publicContext;

    public SecureEnvelopeMetadata(ReadOnlySpan<byte> keyIdentifier, ReadOnlySpan<byte> publicContext = default)
    {
        _keyIdentifier = keyIdentifier.ToArray();
        _publicContext = publicContext.ToArray();
    }

    /// <summary>Identifies which key material a recipient should use. Non-empty.</summary>
    public ReadOnlyMemory<byte> KeyIdentifier => _keyIdentifier;

    /// <summary>Caller-defined public binding data. May be empty.</summary>
    public ReadOnlyMemory<byte> PublicContext => _publicContext;

    public bool Equals(SecureEnvelopeMetadata? other) =>
        other is not null &&
        _keyIdentifier.AsSpan().SequenceEqual(other._keyIdentifier) &&
        _publicContext.AsSpan().SequenceEqual(other._publicContext);

    public override bool Equals(object? obj) => Equals(obj as SecureEnvelopeMetadata);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(_keyIdentifier);
        hash.AddBytes(_publicContext);
        return hash.ToHashCode();
    }
}

/// <summary>
/// An immutable parsed/sealed envelope. <see cref="SerializedData"/> is the
/// canonical wire representation. Construct via <see cref="SecureEnvelopeSealer"/>
/// or <see cref="Parse(System.ReadOnlySpan{byte})"/>.
/// </summary>
public sealed class SecureEnvelope
{
    private readonly byte[] _salt;
    private readonly byte[] _nonce;
    private readonly byte[] _ciphertext;
    private readonly byte[] _tag;
    private readonly byte[] _serializedData;
    private readonly byte[] _authenticatedHeader;

    private SecureEnvelope(
        byte version,
        SecureEnvelopeSuite suite,
        SecureEnvelopeMetadata metadata,
        byte[] salt,
        byte[] nonce,
        byte[] ciphertext,
        byte[] tag,
        byte[] serializedData,
        byte[] authenticatedHeader)
    {
        Version = version;
        Suite = suite;
        Metadata = metadata;
        _salt = salt;
        _nonce = nonce;
        _ciphertext = ciphertext;
        _tag = tag;
        _serializedData = serializedData;
        _authenticatedHeader = authenticatedHeader;
    }

    public byte Version { get; }
    public SecureEnvelopeSuite Suite { get; }
    public SecureEnvelopeMetadata Metadata { get; }
    public ReadOnlyMemory<byte> Salt => _salt;
    public ReadOnlyMemory<byte> Nonce => _nonce;
    public ReadOnlyMemory<byte> Ciphertext => _ciphertext;
    public ReadOnlyMemory<byte> Tag => _tag;
    public ReadOnlyMemory<byte> SerializedData => _serializedData;

    internal ReadOnlySpan<byte> AuthenticatedHeader => _authenticatedHeader;

    /// <summary>Parses and strictly validates a serialized envelope.</summary>
    public static SecureEnvelope Parse(ReadOnlySpan<byte> serializedData)
    {
        var envelope = SecureEnvelopeWireFormat.Decode(serializedData);
        if (!envelope._serializedData.AsSpan().SequenceEqual(serializedData))
        {
            throw SecureEnvelopeException.Malformed();
        }
        return envelope;
    }

    internal static SecureEnvelope Build(
        byte version,
        SecureEnvelopeSuite suite,
        SecureEnvelopeMetadata metadata,
        byte[] salt,
        byte[] nonce,
        byte[] ciphertext,
        byte[] tag)
    {
        SecureEnvelopeWireFormat.ValidateMetadata(metadata);
        if (version != SecureEnvelopeWireFormat.Version)
        {
            throw SecureEnvelopeException.UnsupportedVersion(version);
        }
        if (salt.Length != SecureEnvelopeWireFormat.SaltByteCount ||
            nonce.Length != SecureEnvelopeWireFormat.NonceByteCount ||
            tag.Length != SecureEnvelopeWireFormat.TagByteCount)
        {
            throw SecureEnvelopeException.Malformed();
        }

        var header = SecureEnvelopeWireFormat.HeaderBytes(
            version, suite, metadata, salt, nonce, ciphertext.Length, tag.Length);

        var serialized = new byte[header.Length + ciphertext.Length + tag.Length];
        Buffer.BlockCopy(header, 0, serialized, 0, header.Length);
        Buffer.BlockCopy(ciphertext, 0, serialized, header.Length, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, serialized, header.Length + ciphertext.Length, tag.Length);

        return new SecureEnvelope(
            version,
            suite,
            metadata,
            (byte[])salt.Clone(),
            (byte[])nonce.Clone(),
            (byte[])ciphertext.Clone(),
            (byte[])tag.Clone(),
            serialized,
            header);
    }
}

/// <summary>Seals plaintext into a <see cref="SecureEnvelope"/>.</summary>
public sealed class SecureEnvelopeSealer
{
    private readonly Func<int, byte[]> _randomBytes;

    public SecureEnvelopeSealer()
        : this(SecureRandomBytes.Generate)
    {
    }

    internal SecureEnvelopeSealer(Func<int, byte[]> randomBytes)
    {
        _randomBytes = randomBytes;
    }

    public SecureEnvelope Seal(ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> keyMaterial, SecureEnvelopeMetadata metadata)
    {
        var salt = _randomBytes(SecureEnvelopeWireFormat.SaltByteCount);
        var nonce = _randomBytes(SecureEnvelopeWireFormat.NonceByteCount);
        return Seal(plaintext, keyMaterial, metadata, salt, nonce);
    }

    internal SecureEnvelope Seal(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> keyMaterial,
        SecureEnvelopeMetadata metadata,
        byte[] salt,
        byte[] nonce)
    {
        SecureEnvelopeCrypto.ValidateKeyMaterial(keyMaterial);
        SecureEnvelopeWireFormat.ValidateMetadata(metadata);
        if (salt.Length != SecureEnvelopeWireFormat.SaltByteCount ||
            nonce.Length != SecureEnvelopeWireFormat.NonceByteCount)
        {
            throw SecureEnvelopeException.Malformed();
        }

        var header = SecureEnvelopeWireFormat.HeaderBytes(
            SecureEnvelopeWireFormat.Version,
            SecureEnvelopeSuite.V1Aes256GcmHkdfSha256,
            metadata,
            salt,
            nonce,
            plaintext.Length,
            SecureEnvelopeWireFormat.TagByteCount);

        var key = SecureEnvelopeCrypto.DeriveContentKey(keyMaterial, salt, SecureEnvelopeSuite.V1Aes256GcmHkdfSha256);
        var (ciphertext, tag) = SecureEnvelopeCrypto.Seal(plaintext, key, nonce, header);

        return SecureEnvelope.Build(
            SecureEnvelopeWireFormat.Version,
            SecureEnvelopeSuite.V1Aes256GcmHkdfSha256,
            metadata,
            salt,
            nonce,
            ciphertext,
            tag);
    }
}

/// <summary>Opens a <see cref="SecureEnvelope"/> back to plaintext.</summary>
public sealed class SecureEnvelopeOpener
{
    public byte[] Open(ReadOnlySpan<byte> serializedData, ReadOnlySpan<byte> keyMaterial) =>
        Open(SecureEnvelope.Parse(serializedData), keyMaterial);

    public byte[] Open(SecureEnvelope envelope, ReadOnlySpan<byte> keyMaterial)
    {
        SecureEnvelopeCrypto.ValidateKeyMaterial(keyMaterial);
        var key = SecureEnvelopeCrypto.DeriveContentKey(keyMaterial, envelope.Salt.Span, envelope.Suite);
        return SecureEnvelopeCrypto.Open(
            envelope.Ciphertext.Span,
            envelope.Tag.Span,
            key,
            envelope.Nonce.Span,
            envelope.AuthenticatedHeader);
    }
}

/// <summary>Caller-owned result returned by <see cref="SecureEnvelopePreview"/>.</summary>
public sealed class SecureEnvelopePreviewResult
{
    internal SecureEnvelopePreviewResult(SecureEnvelopeMetadata metadata, byte[] plaintext)
    {
        Metadata = metadata;
        _plaintext = plaintext;
    }

    private readonly byte[] _plaintext;

    public SecureEnvelopeMetadata Metadata { get; }
    public ReadOnlyMemory<byte> Plaintext => _plaintext;
}

/// <summary>
/// Preview-safe helper for small, caller-provided preview payloads. It parses
/// metadata, authenticates the deterministic header as AAD, decrypts a bounded
/// payload, and returns caller-owned display data. It bounds serialized envelope,
/// public metadata, and plaintext bytes; parsed metadata remains an untrusted
/// routing hint until AEAD verification succeeds. It has no storage, network,
/// sync, ratchet, ML-KEM, or notification-UI dependencies.
/// </summary>
public sealed class SecureEnvelopePreview
{
    public SecureEnvelopePreview(
        int maxPlaintextBytes = 4096,
        int maxSerializedEnvelopeBytes = 16 * 1024,
        int maxPublicMetadataBytes = 1024)
    {
        MaxPlaintextBytes = maxPlaintextBytes;
        MaxSerializedEnvelopeBytes = maxSerializedEnvelopeBytes;
        MaxPublicMetadataBytes = maxPublicMetadataBytes;
    }

    public int MaxPlaintextBytes { get; }
    public int MaxSerializedEnvelopeBytes { get; }
    public int MaxPublicMetadataBytes { get; }

    public SecureEnvelopePreviewResult Open(ReadOnlySpan<byte> serializedData, ReadOnlySpan<byte> keyMaterial)
    {
        if (MaxSerializedEnvelopeBytes < 0 || serializedData.Length > MaxSerializedEnvelopeBytes)
        {
            throw SecureEnvelopeException.PreviewPayloadTooLarge();
        }

        var envelope = SecureEnvelope.Parse(serializedData);
        var metadataByteCount = (long)envelope.Metadata.KeyIdentifier.Length + envelope.Metadata.PublicContext.Length;
        if (MaxPublicMetadataBytes < 0 ||
            metadataByteCount > MaxPublicMetadataBytes ||
            MaxPlaintextBytes < 0 ||
            envelope.Ciphertext.Length > MaxPlaintextBytes)
        {
            throw SecureEnvelopeException.PreviewPayloadTooLarge();
        }

        var plaintext = new SecureEnvelopeOpener().Open(envelope, keyMaterial);
        if (plaintext.Length > MaxPlaintextBytes)
        {
            throw SecureEnvelopeException.PreviewPayloadTooLarge();
        }

        return new SecureEnvelopePreviewResult(envelope.Metadata, plaintext);
    }
}
