# SecureEnvelopeKit Security Notes (.NET)

These notes cover the .NET (`System.Security.Cryptography`) implementation. The
shared, cross-platform security model is at
[`../../../docs/SECURITY.md`](../../../docs/SECURITY.md) and the normative format
is in [`../../../docs/spec/secure-envelope-v1.md`](../../../docs/spec/secure-envelope-v1.md).

## Provider-backed primitives

The implementation uses only BCL primitives; it does not implement AES, SHA-256,
HMAC internals, GCM, HKDF, or random generation:

- **AES-256-GCM** via `System.Security.Cryptography.AesGcm`, constructed with an
  explicit 16-byte tag size. The deterministic envelope header is supplied as
  Additional Authenticated Data to `Encrypt`/`Decrypt`. The ciphertext and the
  16-byte tag are stored as separate envelope fields.
- **HKDF-SHA-256** via the built-in `System.Security.Cryptography.HKDF`
  (`DeriveKey` with `HashAlgorithmName.SHA256`). A built-in HKDF is preferred
  over a hand-rolled construction; it is pinned to an RFC 5869 test vector and to
  the shared fixture's derived key.
- **Randomness** for the 32-byte salt and 12-byte nonce via
  `RandomNumberGenerator.Fill`. A fresh salt and nonce are generated per seal.

## Authentication and failure handling

Any AEAD verification failure on open — wrong key material, tampered header or
public metadata, tampered ciphertext, or tampered tag — surfaces as
`SecureEnvelopeException` with `Error == SecureEnvelopeError.AuthenticationFailed`.
`AuthenticationTagMismatchException` (a `CryptographicException`) is caught and
mapped to that single outcome so the caller cannot distinguish failure causes and
no plaintext is returned. Malformed input, unknown versions, unknown suites,
invalid fixed lengths, empty key identifiers, truncation, and trailing bytes are
rejected before any decryption.

## Public metadata

`KeyIdentifier` and `PublicContext` are authenticated but world-readable. Do not
place secrets in them. Metadata bytes are defensively copied on construction and
exposed as `ReadOnlyMemory<byte>`.

## Scope boundaries

This library has no dependency on Windows DPAPI, CNG key storage, certificate
stores, networking, history sync, ratchets, ML-KEM, or notification UI. Key
storage/wrapping belongs in a separate optional adapter, not in the envelope
core. The preview helper only parses metadata, authenticates the header as AAD,
decrypts a bounded payload, and returns caller-owned display data.
