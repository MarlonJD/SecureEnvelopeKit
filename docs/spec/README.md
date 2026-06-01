# Secure Envelope Specification

This directory holds the product-independent, language-neutral contract for the
Secure Envelope protocol. It is the source of truth that every platform
implementation in `platforms/` conforms to.

## Documents

- [`secure-envelope-v1.md`](secure-envelope-v1.md) — the v1 wire format,
  cryptographic parameters, encoding/decoding rules, rejection rules, error
  taxonomy, and preview-helper contract.

## Shared fixture

The canonical interoperability vector lives at
[`../../fixtures/SecureEnvelopeV1/secure-envelope-v1.json`](../../fixtures/SecureEnvelopeV1/secure-envelope-v1.json).
Each platform's test suite both reproduces the envelope bytes from the fixture
inputs (proving the encrypt direction matches) and opens the committed envelope
bytes to recover the plaintext (proving the decrypt direction matches). All hex
fields use lowercase, no `0x` prefix.

| Field | Meaning |
| --- | --- |
| `fixtureVersion`, `status`, `name` | fixture metadata; `status: stable` means the bytes are frozen |
| `version`, `suite`, `suiteIdHex` | envelope version `1`, suite `v1AES256GCMHKDFSHA256` / `0001` |
| `hkdfInfoUtf8` | the HKDF `info` string, as UTF-8 text |
| `keyMaterialHex` | input key material (IKM) for HKDF |
| `saltHex`, `nonceHex` | the 32-byte salt and 12-byte nonce |
| `keyIdentifierHex`, `publicContextHex` | public metadata |
| `plaintextHex` | the payload that was sealed |
| `derivedContentKeyHex` | expected HKDF output (AES-256 key) |
| `authenticatedHeaderHex` | expected authenticated header (AAD) bytes |
| `ciphertextHex`, `tagHex` | expected AES-256-GCM outputs |
| `envelopeHex` | the full serialized envelope (`header \|\| ciphertext \|\| tag`) |

## Changing the contract

Treat any change to the envelope bytes, authenticated header, HKDF `info`, or
derived key as a wire-format compatibility change. Coordinate it across all
platform packages and version it (see section 12 of the v1 spec) rather than
mutating v1 semantics in place.
