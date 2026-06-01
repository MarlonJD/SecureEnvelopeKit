namespace SecureEnvelopeKit;

/// <summary>
/// Deterministic v1 binary encoder/decoder. All multi-byte integers are
/// unsigned big-endian. The header (everything up to and including the tag
/// length byte) is the AES-GCM Additional Authenticated Data.
/// </summary>
internal static class SecureEnvelopeWireFormat
{
    internal static readonly byte[] Magic = [0x53, 0x45, 0x4B]; // "SEK"
    internal const byte Version = 1;
    internal const int SaltByteCount = 32;
    internal const int NonceByteCount = 12;
    internal const int TagByteCount = 16;

    private const int U16Max = 0xFFFF;

    // A .NET array/Memory length is a non-negative int, so it always fits the
    // u32 public-context and ciphertext length fields; only the u16 key
    // identifier length needs an upper-bound guard.
    internal static void ValidateMetadata(SecureEnvelopeMetadata metadata)
    {
        var keyIdentifierLength = metadata.KeyIdentifier.Length;
        if (keyIdentifierLength == 0 || keyIdentifierLength > U16Max)
        {
            throw SecureEnvelopeException.InvalidMetadata();
        }
    }

    internal static byte[] HeaderBytes(
        byte version,
        SecureEnvelopeSuite suite,
        SecureEnvelopeMetadata metadata,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> nonce,
        int ciphertextByteCount,
        int tagByteCount)
    {
        ValidateMetadata(metadata);
        if (ciphertextByteCount < 0)
        {
            throw SecureEnvelopeException.Malformed();
        }
        if (salt.Length != SaltByteCount || nonce.Length != NonceByteCount || tagByteCount != TagByteCount)
        {
            throw SecureEnvelopeException.Malformed();
        }

        var keyIdentifier = metadata.KeyIdentifier.Span;
        var publicContext = metadata.PublicContext.Span;
        var buffer = new List<byte>(
            Magic.Length + 1 + 2 + 2 + keyIdentifier.Length + 4 + publicContext.Length +
            1 + salt.Length + 1 + nonce.Length + 4 + 1);

        buffer.AddRange(Magic);
        buffer.Add(version);
        WriteU16(buffer, (int)suite);
        WriteU16(buffer, keyIdentifier.Length);
        AddRange(buffer, keyIdentifier);
        WriteU32(buffer, publicContext.Length);
        AddRange(buffer, publicContext);
        buffer.Add((byte)salt.Length);
        AddRange(buffer, salt);
        buffer.Add((byte)nonce.Length);
        AddRange(buffer, nonce);
        WriteU32(buffer, ciphertextByteCount);
        buffer.Add((byte)tagByteCount);
        return [.. buffer];
    }

    internal static SecureEnvelope Decode(ReadOnlySpan<byte> data)
    {
        var reader = new ByteReader(data);

        var magic = reader.ReadBytes(Magic.Length);
        if (!magic.AsSpan().SequenceEqual(Magic))
        {
            throw SecureEnvelopeException.Malformed();
        }

        int version = reader.ReadU8();
        if (version != Version)
        {
            throw SecureEnvelopeException.UnsupportedVersion(version);
        }

        int suiteId = reader.ReadU16();
        var suite = (SecureEnvelopeSuite)suiteId;
        if (!Enum.IsDefined(suite))
        {
            throw SecureEnvelopeException.UnsupportedSuite(suiteId);
        }

        int keyIdentifierLength = reader.ReadU16();
        if (keyIdentifierLength == 0)
        {
            throw SecureEnvelopeException.Malformed();
        }
        var keyIdentifier = reader.ReadBytes(keyIdentifierLength);

        var publicContext = reader.ReadBytes(reader.ReadU32());

        int saltLength = reader.ReadU8();
        var salt = reader.ReadBytes(saltLength);
        if (salt.Length != SaltByteCount)
        {
            throw SecureEnvelopeException.Malformed();
        }

        int nonceLength = reader.ReadU8();
        var nonce = reader.ReadBytes(nonceLength);
        if (nonce.Length != NonceByteCount)
        {
            throw SecureEnvelopeException.Malformed();
        }

        long ciphertextLength = reader.ReadU32();
        int tagLength = reader.ReadU8();
        if (tagLength != TagByteCount)
        {
            throw SecureEnvelopeException.Malformed();
        }

        int headerLength = reader.Offset;
        var ciphertext = reader.ReadBytes(ciphertextLength);
        var tag = reader.ReadBytes(tagLength);
        if (!reader.IsAtEnd)
        {
            throw SecureEnvelopeException.Malformed();
        }

        var metadata = new SecureEnvelopeMetadata(keyIdentifier, publicContext);
        ValidateMetadata(metadata);

        var envelope = SecureEnvelope.Build((byte)version, suite, metadata, salt, nonce, ciphertext, tag);
        if (envelope.AuthenticatedHeader.Length != headerLength)
        {
            throw SecureEnvelopeException.Malformed();
        }
        return envelope;
    }

    private static void WriteU16(List<byte> buffer, int value)
    {
        buffer.Add((byte)((value >> 8) & 0xFF));
        buffer.Add((byte)(value & 0xFF));
    }

    private static void WriteU32(List<byte> buffer, long value)
    {
        buffer.Add((byte)((value >> 24) & 0xFF));
        buffer.Add((byte)((value >> 16) & 0xFF));
        buffer.Add((byte)((value >> 8) & 0xFF));
        buffer.Add((byte)(value & 0xFF));
    }

    private static void AddRange(List<byte> buffer, ReadOnlySpan<byte> bytes)
    {
        foreach (var b in bytes)
        {
            buffer.Add(b);
        }
    }

    private ref struct ByteReader(ReadOnlySpan<byte> data)
    {
        private readonly ReadOnlySpan<byte> _data = data;
        private int _offset = 0;

        public readonly int Offset => _offset;

        public readonly bool IsAtEnd => _offset == _data.Length;

        public byte ReadU8() => ReadBytes(1)[0];

        public int ReadU16()
        {
            var bytes = ReadBytes(2);
            return (bytes[0] << 8) | bytes[1];
        }

        public long ReadU32()
        {
            var bytes = ReadBytes(4);
            long value = 0;
            foreach (var b in bytes)
            {
                value = (value << 8) | b;
            }
            return value;
        }

        public byte[] ReadBytes(int count) => ReadBytes((long)count);

        public byte[] ReadBytes(long count)
        {
            if (count < 0 || count > (long)(_data.Length - _offset))
            {
                throw SecureEnvelopeException.Malformed();
            }
            int length = (int)count;
            var result = _data.Slice(_offset, length).ToArray();
            _offset += length;
            return result;
        }
    }
}
