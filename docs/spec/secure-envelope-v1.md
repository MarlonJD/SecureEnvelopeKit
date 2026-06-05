# Secure Envelope v1 Wire Format

Status: stable

This document is the product-independent, language-neutral contract for the
Secure Envelope v1 format. The Swift (`platforms/swift`), Android/Kotlin
(`platforms/android`), and .NET (`platforms/dotnet`) implementations in this
repository all conform to this specification and to the shared test vector in
[`fixtures/SecureEnvelopeV1/secure-envelope-v1.json`](../../fixtures/SecureEnvelopeV1/secure-envelope-v1.json).

A conforming implementation produces byte-identical envelopes given identical
inputs and decodes/authenticates envelopes produced by any other conforming
implementation.

## 1. Scope

A Secure Envelope binds caller-provided **public metadata** to a confidential
payload using authenticated encryption. The envelope provides:

- Confidentiality and integrity of the payload (ciphertext + authentication tag).
- Integrity/authenticity of the public header, including the public metadata
  (the header is authenticated as Additional Authenticated Data, not encrypted).
- A deterministic, versioned binary representation suitable for storage and
  transport.

Out of scope (the caller or a higher layer owns these): key agreement, ML-KEM,
identity, sessions, ratchets, persistence, networking, history sync, and
notification UI. This includes Triple Ratchet, Sparse Post-Quantum Ratchet,
Double Ratchet, session state, skipped-message keys, prekey claiming, replay
windows, roster verification, transcript signatures, message repair, and full
message decrypt. The caller supplies input key material; the envelope does not
create or manage it.

## 2. Terminology and constants

| Name | Value |
| --- | --- |
| Magic | ASCII `SEK` = `0x53 0x45 0x4B` |
| Version | `1` (one byte) |
| Suite id (v1) | `0x0001` (`v1AES256GCMHKDFSHA256`) |
| Salt length | 32 bytes |
| Nonce length | 12 bytes (96-bit AES-GCM nonce) |
| Tag length | 16 bytes (128-bit AES-GCM tag) |
| Minimum input key material | 32 bytes |
| Derived content key length | 32 bytes (AES-256) |
| Integer encoding | unsigned, big-endian |

All multi-byte integers in the wire format are unsigned big-endian.

## 3. Suite registry

| Suite id | Name | AEAD | KDF | Notes |
| --- | --- | --- | --- | --- |
| `0x0001` | `v1AES256GCMHKDFSHA256` | AES-256-GCM | HKDF-SHA-256 | The only suite defined for v1. |

An implementation MUST reject any suite id it does not recognize.

## 4. Cryptographic parameters (suite `0x0001`)

### 4.1 Content-key derivation — HKDF-SHA-256 (RFC 5869)

```
content_key = HKDF-SHA-256(
    IKM  = input_key_material,        # caller-supplied, >= 32 bytes
    salt = envelope.salt,             # 32 random bytes, stored in the header
    info = UTF-8("SecureEnvelopeKit/v1/aes-256-gcm+hkdf-sha256"),
    L    = 32                         # AES-256 key length
)
```

`info` is the exact UTF-8 byte string
`SecureEnvelopeKit/v1/aes-256-gcm+hkdf-sha256` (no NUL terminator, no quotes).
HKDF is the full extract-then-expand construction from RFC 5869. Implementations
that lack a built-in HKDF MUST construct it over a provider-backed HMAC-SHA-256
and validate against RFC 5869 test vectors.

### 4.2 Authenticated encryption — AES-256-GCM

```
(ciphertext, tag) = AES-256-GCM-Seal(
    key   = content_key,              # 32 bytes from 4.1
    nonce = envelope.nonce,           # 12 random bytes, stored in the header
    aad   = authenticated_header,     # section 5.2
    plaintext = payload
)
```

`ciphertext` has the same length as `plaintext`. `tag` is 16 bytes. Opening runs
the inverse and MUST fail if authentication does not verify.

### 4.3 Randomness

`salt` and `nonce` MUST be generated with an OS/provider-backed cryptographically
secure random source. A fresh `salt` and a fresh `nonce` MUST be generated for
each `seal` operation. Implementations MUST NOT implement their own RNG, AES,
SHA-256, HMAC, GCM, or HKDF primitives; they MUST use platform/provider crypto.

## 5. Binary layout

### 5.1 Field order

Fields appear in exactly this order. "u8/u16/u32" denote unsigned big-endian
integers of 1/2/4 bytes.

| # | Field | Type | Notes |
| --- | --- | --- | --- |
| 1 | magic | 3 bytes | `0x53 0x45 0x4B` |
| 2 | version | u8 | `1` |
| 3 | suite | u16 | `0x0001` |
| 4 | key_identifier_length | u16 | `>= 1` |
| 5 | key_identifier | bytes | length from field 4 |
| 6 | public_context_length | u32 | may be `0` |
| 7 | public_context | bytes | length from field 6 |
| 8 | salt_length | u8 | MUST equal `32` |
| 9 | salt | 32 bytes | |
| 10 | nonce_length | u8 | MUST equal `12` |
| 11 | nonce | 12 bytes | |
| 12 | ciphertext_length | u32 | |
| 13 | tag_length | u8 | MUST equal `16` |
| 14 | ciphertext | bytes | length from field 12 |
| 15 | tag | 16 bytes | |

Fields 1–13 are the **authenticated header**. Fields 14–15 are the payload.

### 5.2 Authenticated header (AAD)

The authenticated header is the contiguous byte range covering fields 1 through
13 (magic through `tag_length`, inclusive), i.e. every header byte up to but not
including the ciphertext. These exact bytes are passed to AES-GCM as Additional
Authenticated Data on both seal and open. The header is authenticated but not
encrypted; therefore the public metadata (`key_identifier`, `public_context`) is
integrity-protected but world-readable.

## 6. Public metadata

- `key_identifier` (field 5): non-empty, up to 65535 bytes. Identifies which key
  material a recipient should use. MUST NOT be empty.
- `public_context` (field 7): 0 to 4294967295 bytes of caller-defined public
  binding data (for example a routing/preview hint).

Both are authenticated public data. Callers MUST NOT place secrets in either
field.

During decode, metadata becomes authenticated only after AES-GCM open succeeds
with the expected key material. A parser may expose `key_identifier` before
authentication so callers can locate candidate key material, but callers MUST
treat parsed metadata as an untrusted hint until AEAD verification succeeds.
Security decisions that depend on `public_context` MUST either wait for a
successful open or be checked against independently trusted surrounding context.

## 7. Encoding (seal)

1. Validate `input_key_material` length `>= 32`; else `invalidKeyMaterial`.
2. Validate metadata: `key_identifier` non-empty and `<= 65535` bytes;
   `public_context` `<= 4294967295` bytes; else `invalidMetadata`.
3. Generate a fresh 32-byte `salt` and 12-byte `nonce` from secure randomness
   (or accept caller-supplied values only in deterministic test paths).
4. Build the authenticated header (fields 1–13) using `ciphertext_length =
   plaintext length` and `tag_length = 16`.
5. Derive `content_key` per section 4.1.
6. Compute `(ciphertext, tag)` per section 4.2 with the header as AAD.
7. Emit `authenticated_header || ciphertext || tag`.

## 8. Decoding (open) and rejection rules

Parsing MUST be strict. An implementation MUST reject (typically as
`malformedEnvelope` unless a more specific case applies):

1. `magic` not equal to `SEK`.
2. `version != 1` → `unsupportedVersion`.
3. unknown `suite` → `unsupportedSuite`.
4. `key_identifier_length == 0` (empty key identifier).
5. `salt_length != 32`, `nonce_length != 12`, or `tag_length != 16`.
6. any length prefix that runs past the end of the input (truncation).
7. trailing bytes after the tag (the envelope MUST consume the input exactly).
8. a re-encoded header that does not byte-match the parsed header bytes.

After a structurally valid parse, the implementation derives the content key and
runs AES-256-GCM open with the parsed header as AAD. Any authentication failure
(wrong key material, tampered header/metadata, tampered ciphertext, tampered
tag) MUST surface as `authenticationFailed` and MUST NOT return plaintext.

Decoding MUST NOT leak why authentication failed beyond the single
`authenticationFailed` outcome.

## 9. Error taxonomy

Conforming implementations expose at least these logical error cases (names may
follow each language's conventions):

| Case | Meaning |
| --- | --- |
| `malformedEnvelope` | structural decode failure (bad magic, truncation, trailing bytes, bad fixed length, header mismatch) |
| `unsupportedVersion` | version byte is not `1` |
| `unsupportedSuite` | suite id is not in the registry |
| `invalidKeyMaterial` | input key material shorter than 32 bytes |
| `invalidMetadata` | empty key identifier or oversized metadata |
| `authenticationFailed` | AEAD verification failed on open |
| `randomnessUnavailable` | secure RNG could not produce bytes |
| `previewPayloadTooLarge` | preview helper bound exceeded (section 10) |

## 10. Preview helper contract

A preview helper is an optional, dependency-free convenience for small,
caller-provided preview payloads (for example notification previews). It MUST:

- parse the envelope and read the public metadata,
- authenticate the deterministic header bytes as AAD,
- decrypt only a small payload bounded by a caller-supplied maximum size,
- reject payloads exceeding that maximum (`previewPayloadTooLarge`), ideally
  before doing AEAD work using the declared `ciphertext_length`,
- return only caller-owned display data (the metadata and decrypted bytes).

A preview helper MUST NOT access storage, network, history sync, ratchets,
ML-KEM, full-message decryption pipelines, or notification UI.

For untrusted preview inputs, implementations SHOULD also apply caller-defined
serialized-envelope, authenticated-header, or public-metadata byte budgets before
decryption. These resource limits do not change the v1 wire format; they are
operational guardrails for memory-constrained preview surfaces.

## 11. Conformance

An implementation conforms to v1 if, using the inputs in the shared fixture
([`fixtures/SecureEnvelopeV1/secure-envelope-v1.json`](../../fixtures/SecureEnvelopeV1/secure-envelope-v1.json)),
it reproduces:

- `derivedContentKeyHex` from HKDF (section 4.1),
- `authenticatedHeaderHex` (fields 1–13),
- `ciphertextHex` and `tagHex` from AES-256-GCM (section 4.2),
- `envelopeHex` (the full serialized envelope),

and, decoding `envelopeHex`, recovers `plaintextHex` while enforcing every
rejection rule in section 8.

Because AES-256-GCM and HKDF-SHA-256 are standardized, byte-equality with the
fixture is sufficient to guarantee cross-language interoperability in both
directions (encrypt on platform A, decrypt on platform B).

## 12. Versioning policy

The version byte and suite id are the compatibility anchors. Any change to field
order, lengths, the `info` string, or the AAD definition is a new wire version.
Implementations MUST keep rejecting unknown versions and suites rather than
guessing. Do not silently change v1 semantics after release; introduce a new
version instead.
