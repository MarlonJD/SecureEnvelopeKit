# SecureEnvelopeKit (.NET)

Product-independent secure envelope protocol kit — the .NET implementation,
Windows-friendly while usable from any standard .NET consumer. This is one
platform of the [SecureEnvelopeKit monorepo](../../README.md); the
language-neutral contract and shared fixture live at the repository root under
[`docs/spec/`](../../docs/spec/secure-envelope-v1.md) and
[`fixtures/`](../../fixtures/SecureEnvelopeV1/secure-envelope-v1.json).

## Overview

`SecureEnvelopeKit` is a `net10.0` class library that seals caller-provided
payloads into a deterministic, versioned binary envelope using AES-256-GCM with
an HKDF-SHA-256 content key, and opens them again. It conforms byte-for-byte to
the shared v1 wire format, so envelopes interoperate with the Swift and Kotlin
implementations.

The library targets `net10.0` (not a Windows-only TFM) so it builds and tests
cross-platform and is consumable by a Windows app as well as by standard .NET
consumers. It is product-independent: no app state, accounts, databases,
notification UI, networking, ratchets, ML-KEM, or message history. Windows
DPAPI, CNG key storage, and certificate stores are intentionally out of scope
for the envelope core.

## Build and test

From this directory:

```sh
dotnet test
```

The solution is `SecureEnvelopeKit.slnx` (the .NET 10 default solution format).
Tests use xUnit and cover round-trip, wrong-key, tampered header/ciphertext/tag,
malformed decode, stable encoding, preview behavior, HKDF determinism, an
RFC 5869 HKDF-SHA-256 vector, and cross-platform parity against the shared Swift
fixture (reproducing the bytes and opening the committed envelope).

Requires the .NET 10 SDK.

## Quick start

```csharp
using SecureEnvelopeKit;

byte[] keyMaterial = /* >= 32 bytes from your key agreement / ratchet */;
var metadata = new SecureEnvelopeMetadata(
    keyIdentifier: "recipient-key-v1"u8,
    publicContext: "preview"u8);

var envelope = new SecureEnvelopeSealer().Seal("hello"u8, keyMaterial, metadata);

ReadOnlyMemory<byte> bytes = envelope.SerializedData;          // canonical wire bytes
byte[] plaintext = new SecureEnvelopeOpener().Open(bytes.Span, keyMaterial);
```

For notification-style previews:

```csharp
var preview = new SecureEnvelopePreview(
    maxPlaintextBytes: 4096,
    maxSerializedEnvelopeBytes: 16 * 1024,
    maxPublicMetadataBytes: 1024);
SecureEnvelopePreviewResult result = preview.Open(bytes.Span, keyMaterial);
// result.Metadata, result.Plaintext
```

Preview helpers bound the serialized envelope, public metadata, and plaintext
display payload. Parsed metadata is a routing hint until AEAD verification
succeeds with the expected key material.

## Algorithms

`SecureEnvelopeSuite.V1Aes256GcmHkdfSha256` uses:

- AES-256-GCM via `System.Security.Cryptography.AesGcm` (12-byte nonce, 16-byte tag).
- HKDF-SHA-256 via the built-in `System.Security.Cryptography.HKDF`.
- A 32-byte random salt and 12-byte random nonce via `RandomNumberGenerator`.

The library does not implement AES, SHA-256, HMAC internals, GCM, HKDF, or RNG
by hand.

## Wire format and security

The binary format, AAD rules, and rejection behavior are specified in
[`docs/spec/secure-envelope-v1.md`](../../docs/spec/secure-envelope-v1.md).
Platform security notes are in [`docs/SECURITY.md`](docs/SECURITY.md); the shared
model is in [`../../docs/SECURITY.md`](../../docs/SECURITY.md).

## Non-goals

No ML-KEM or key agreement, ratchets, sessions, databases, networking, history
sync, full-message decrypt pipelines, notification UI, DPAPI/CNG storage
adapters, account recovery, or server-side storage. There is no separate
`SecureEnvelopeDotNet` repository; this is the .NET platform of the single
SecureEnvelopeKit repository.
