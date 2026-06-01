# SecureEnvelopeKit Security Model

This is the shared, cross-platform security model. Each platform package adds
provider-specific notes in its own `docs/SECURITY.md`
([Swift](../platforms/swift/docs/SECURITY.md),
[Android](../platforms/android/docs/SECURITY.md),
[.NET](../platforms/dotnet/docs/SECURITY.md)). The normative format is defined in
[`docs/spec/secure-envelope-v1.md`](spec/secure-envelope-v1.md).

## What it protects

SecureEnvelopeKit applies authenticated encryption to caller-provided payload
bytes and binds caller-provided public metadata to that payload. It assumes the
caller already holds suitable input key material from a higher-level key
agreement, ratchet, or key-management system. The package does not create
identities, establish sessions, advance ratchets, persist secrets, or contact
remote services.

## Algorithms (suite `v1AES256GCMHKDFSHA256`)

- AES-256-GCM for authenticated encryption (12-byte nonce, 16-byte tag).
- HKDF-SHA-256 for per-envelope content-key derivation (32-byte salt, 32-byte
  output, fixed `info` string).
- OS/provider-backed CSPRNG for the salt and nonce.

Every platform uses its reviewed, provider-backed crypto and must not hand-roll
AES, SHA-256, HMAC, GCM, HKDF internals, or random generation:

- Swift: CryptoKit (`AES.GCM`, `HKDF<SHA256>`) and Security.framework randomness.
- Android/JVM: JCA `Cipher("AES/GCM/NoPadding")`, RFC 5869 HKDF over
  `Mac("HmacSHA256")`, and `SecureRandom`.
- .NET: `System.Security.Cryptography.AesGcm`, built-in `HKDF`, and
  `RandomNumberGenerator`.

## Public metadata is authenticated, not encrypted

The deterministic header — version, suite, `key_identifier`, `public_context`,
salt, nonce, ciphertext length, and tag length — is passed to AES-GCM as
Additional Authenticated Data. It is integrity-protected but world-readable.
Treat `key_identifier` and `public_context` as routable public data and never
place plaintext secrets in either field. Public metadata can still leak routing
information even when payload confidentiality holds; bind these values to the
surrounding protocol intentionally.

## Tampering and parsing

Field ordering and length prefixes are fixed. Any header or ciphertext tampering,
wrong key material, or tag tampering causes opening to fail with the single
`authenticationFailed` outcome after parsing succeeds, and no plaintext is
returned. Malformed data, unknown versions, unknown suites, invalid fixed
lengths, empty key identifiers, truncation, and trailing bytes are rejected
before any decryption is attempted.

## Preview hot path

Preview helpers are limited to small, caller-provided preview payloads. Keep
preview payloads small and set a maximum size for the display surface. A preview
helper must not become a hidden full-message decryptor, history-sync path,
storage lookup, network path, ratchet-advancement path, or UI renderer, and must
not depend on ML-KEM.

## Caller responsibilities

- Generate or receive at least 32 bytes of strong input key material.
- Keep key material out of logs, analytics, crash reports, and public metadata.
- Bind metadata values to the surrounding protocol so public routing data is
  intentional.
- Version higher-level protocol changes instead of silently changing v1
  semantics.
- Require cross-platform fixture parity before relying on interoperability.

## Wire-format change control

The stable v1 fixture is
[`fixtures/SecureEnvelopeV1/secure-envelope-v1.json`](../fixtures/SecureEnvelopeV1/secure-envelope-v1.json).
Treat any change to its envelope bytes, authenticated header bytes, HKDF `info`,
or derived key as a wire-format compatibility change that must be coordinated
across all platform packages and shipped as a new version, never as a silent
mutation of v1.
