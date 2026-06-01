# SecureEnvelopeKit

Product-independent secure envelope protocol kit.

## Overview

SecureEnvelopeKit is a small SwiftPM package for Apple-platform secure payload
envelopes. It provides deterministic binary envelope serialization, typed
parsing failures, CryptoKit-backed AES-256-GCM encryption, CryptoKit HKDF-SHA-256
content-key derivation, and Security.framework-backed random salt and nonce
generation.

The package is intentionally product-independent. It does not know about app
state, accounts, databases, notification UI, network calls, ratchets, ML-KEM
implementations, or message history.

## Installation

Add the package to an Apple SwiftPM consumer:

```swift
.package(url: "https://github.com/MarlonJD/SecureEnvelopeKit.git", branch: "main")
```

Then depend on the library product:

```swift
.product(name: "SecureEnvelopeKit", package: "SecureEnvelopeKit")
```

Supported platforms:

- iOS 15 and later
- macOS 12 and later

## Quick Start

```swift
import Foundation
import SecureEnvelopeKit

let keyMaterial = Data(repeating: 0x42, count: 32)
let metadata = SecureEnvelopeMetadata(
    keyIdentifier: Data("recipient-key-v1".utf8),
    publicContext: Data("preview".utf8)
)

let envelope = try SecureEnvelopeSealer().seal(
    plaintext: Data("hello".utf8),
    keyMaterial: keyMaterial,
    metadata: metadata
)

let plaintext = try SecureEnvelopeOpener().open(
    envelope: envelope,
    keyMaterial: keyMaterial
)
```

`serializedData` is the canonical wire representation:

```swift
let bytes = envelope.serializedData
let parsed = try SecureEnvelope(serializedData: bytes)
```

## Wire Format

Version 1 uses a fixed-order binary format:

1. Magic bytes: `SEK`
2. Version byte
3. Suite identifier: unsigned 16-bit big-endian
4. Key identifier: unsigned 16-bit byte length, then bytes
5. Public context: unsigned 32-bit byte length, then bytes
6. Salt: unsigned 8-bit byte length, then 32 bytes
7. Nonce: unsigned 8-bit byte length, then 12 bytes
8. Ciphertext length: unsigned 32-bit byte length
9. Tag length: unsigned 8-bit byte length
10. Ciphertext bytes
11. Tag bytes

The deterministic header through the tag-length byte is authenticated as
AES-GCM additional authenticated data. Unknown versions, unknown suites,
truncated fields, empty key identifiers, invalid fixed lengths, and trailing
bytes are rejected.

## Supported Algorithms

`SecureEnvelopeSuite.v1AES256GCMHKDFSHA256` uses:

- AES-256-GCM through CryptoKit for authenticated encryption.
- HKDF-SHA-256 through CryptoKit to derive a per-envelope content key.
- A 32-byte random salt generated through Security.framework.
- A 12-byte random AES-GCM nonce generated through Security.framework.

The caller supplies at least 32 bytes of input key material. That material can
come from a higher-level key agreement or ratchet, but those systems are outside
this package.

## Preview Hot Path

`SecureEnvelopePreview` is for small caller-provided preview payload envelopes.
It parses metadata, authenticates the deterministic header as AAD, decrypts the
preview payload, enforces a caller-owned maximum plaintext size, and returns
`SecureEnvelopePreviewResult`.

The preview helper is synchronous and has no storage, network, synchronization,
ratchet, ML-KEM, history, or notification UI dependencies.

## Non-Goals

SecureEnvelopeKit does not implement:

- ML-KEM or any key agreement primitive.
- Double-ratchet state, session setup, or message history.
- Database, network, search, sync, notification UI, or app extension behavior.
- Account recovery, key backup, or server-side envelope storage.
- Cross-platform implementations. The v1 binary format is designed to be shared
  with other platform implementations later.
