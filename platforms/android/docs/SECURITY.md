# SecureEnvelopeKit Security Notes (Android / Kotlin)

These notes cover the Android/JVM (JCA) implementation. The shared,
cross-platform security model is at
[`../../../docs/SECURITY.md`](../../../docs/SECURITY.md) and the normative format
is in [`../../../docs/spec/secure-envelope-v1.md`](../../../docs/spec/secure-envelope-v1.md).

## Provider-backed primitives

The implementation uses only JCA primitives provided by the platform; it does
not implement AES, SHA-256, HMAC internals, GCM, HKDF, or random generation:

- **AES-256-GCM** via `javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")`
  with a `GCMParameterSpec` of 128-bit tag length and a 12-byte nonce. The
  deterministic envelope header is supplied as Additional Authenticated Data via
  `Cipher.updateAAD(...)` before `doFinal(...)`. JCA returns ciphertext with the
  16-byte tag appended; the envelope stores them as separate fields.
- **HKDF-SHA-256** is the RFC 5869 extract-then-expand construction built over
  `javax.crypto.Mac.getInstance("HmacSHA256")`. The JVM/Android do not expose a
  built-in HKDF on the supported API levels, so the construction is implemented
  over provider HMAC and verified against an RFC 5869 test vector and the shared
  fixture's derived key.
- **Randomness** for the 32-byte salt and 12-byte nonce comes from
  `java.security.SecureRandom`. A fresh salt and nonce are generated per seal.

## Authentication and failure handling

Any AEAD verification failure on open — wrong key material, tampered header or
public metadata, tampered ciphertext, or tampered tag — surfaces as
`SecureEnvelopeException.AuthenticationFailed`. JCA's `AEADBadTagException` (a
`GeneralSecurityException`) is caught and mapped to that single outcome so the
caller cannot distinguish failure causes and no plaintext is returned. Malformed
input, unknown versions, unknown suites, invalid fixed lengths, empty key
identifiers, truncation, and trailing bytes are rejected before any decryption.

## Public metadata

`keyIdentifier` and `publicContext` are authenticated but world-readable. Do not
place secrets in them. Stored metadata arrays are defensively copied on input;
treat exposed arrays as read-only. Parsed metadata is authenticated only after
`SecureEnvelopeOpener` or `SecureEnvelopePreview` successfully verifies AES-GCM
with the expected key material; before that point it is an untrusted routing hint
for key lookup, not an authorization or UI trust signal.

## Scope boundaries

This module has no dependency on the Android framework, Android Keystore,
storage, networking, history sync, ratchets, ML-KEM, or notification UI. Key
storage/wrapping (for example via Android Keystore) is intentionally out of
scope for the envelope core; if needed it belongs in a separate optional module.
The preview helper only parses metadata, authenticates the header as AAD,
decrypts a bounded payload, and returns caller-owned display data. Preview
callers should also bound serialized envelope, authenticated header, and public
metadata sizes before using untrusted bytes in memory-constrained preview paths.
