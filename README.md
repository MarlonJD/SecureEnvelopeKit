# SecureEnvelopeKit

Product-independent secure envelope protocol, implemented natively for Apple,
Android, and .NET from one shared contract and one shared test vector.

A Secure Envelope binds caller-provided public metadata to a confidential
payload using authenticated encryption (AES-256-GCM) with an HKDF-SHA-256
content key. It is deliberately small: it does not know about app state,
accounts, databases, notification UI, networking, ratchets, ML-KEM, or message
history. The caller supplies input key material; everything else is the
envelope's job.

## Repository layout

```text
SecureEnvelopeKit/
  Package.swift                 # thin SwiftPM shim for public consumers -> platforms/swift
  docs/
    SECURITY.md                 # shared, cross-platform security model
    spec/                       # product-independent envelope contract (source of truth)
    plans/                      # implementation plans
  fixtures/
    SecureEnvelopeV1/           # shared v1 wire-format / cross-platform vector
  platforms/
    swift/                      # iOS + macOS (SwiftPM, CryptoKit)
    android/                    # Android/JVM (Gradle + Kotlin, JCA)
    dotnet/                     # Windows/.NET (System.Security.Cryptography)
```

The contract lives in [`docs/spec/secure-envelope-v1.md`](docs/spec/secure-envelope-v1.md)
and the shared interoperability vector in
[`fixtures/SecureEnvelopeV1/secure-envelope-v1.json`](fixtures/SecureEnvelopeV1/secure-envelope-v1.json).
All three implementations conform to both, so an envelope sealed on one platform
opens on the others, byte for byte.

## Platforms

| Platform | Path | Build/test |
| --- | --- | --- |
| Swift (iOS/macOS) | [`platforms/swift`](platforms/swift) | `cd platforms/swift && swift test` |
| Android/Kotlin (JVM) | [`platforms/android`](platforms/android) | `cd platforms/android && ./gradlew test` |
| .NET | [`platforms/dotnet`](platforms/dotnet) | `cd platforms/dotnet && dotnet test` |

Each platform uses only its ecosystem's reviewed, provider-backed crypto. None
of them implement AES, SHA-256, HMAC, GCM, HKDF internals, or RNG by hand.

## Using it

### Swift (SwiftPM)

```swift
.package(url: "https://github.com/MarlonJD/SecureEnvelopeKit.git", branch: "main")
```

```swift
.product(name: "SecureEnvelopeKit", package: "SecureEnvelopeKit")
```

The root `Package.swift` is a compatibility entry point; the canonical Swift
package and tests live under [`platforms/swift`](platforms/swift).

### Android / .NET

See [`platforms/android/README.md`](platforms/android/README.md) and
[`platforms/dotnet/README.md`](platforms/dotnet/README.md) for Gradle and NuGet
usage.

## Cross-platform parity

The shared fixture is the contract's enforcement mechanism. Each platform's
tests both **reproduce** the fixture envelope bytes from its inputs (encrypt
parity) and **open** the committed envelope bytes to recover the plaintext
(decrypt parity). Every platform also verifies that tampering with the header,
ciphertext, or tag fails authentication. Do not integrate a platform into an app
until it passes fixture parity.

## Ratchet boundary

SecureEnvelopeKit is not a Triple Ratchet, Sparse Post-Quantum Ratchet, Double
Ratchet, or session-state implementation. Those belong to a higher-level E2EE
client/session layer.

This package intentionally stops at the versioned envelope boundary:

- deterministic envelope encoding and decoding,
- authenticated header/AAD bytes,
- AES-256-GCM seal/open,
- HKDF-SHA-256 envelope key derivation,
- preview-only open helpers with serialized-envelope, public-metadata, and
  plaintext byte budgets,
- shared cross-platform fixtures.

`key_identifier` and `public_context` are public authenticated metadata. Parsers
may expose them before decryption so callers can find candidate key material,
but those parsed values are attacker-controlled routing hints until AEAD
verification succeeds with the expected key material. Do not use parsed metadata
for authorization, storage writes, UI trust, or protocol state transitions before
a successful open.

Preview helpers are for small caller-provided display payloads. Configure the
serialized envelope, public metadata, and plaintext limits for the target
surface; these limits are preview resource guardrails and do not change the v1
wire format.

A future session layer can consume SecureEnvelopeKit together with an ML-KEM
provider such as `mlkem-kit`, but it must own session state, ratchet
advancement, skipped-message keys, prekey claiming, replay windows, roster
verification, transcript signatures, repair, and full message decrypt.

## Security

See [`docs/SECURITY.md`](docs/SECURITY.md) for the shared security model and each
platform's `docs/SECURITY.md` for provider-specific notes.

## Non-goals

SecureEnvelopeKit does not implement ML-KEM or any key agreement, double-ratchet
state, session setup, message history, databases, networking, notification UI,
account recovery, or server-side storage. The v1 binary format is intentionally
shared across platforms rather than reinvented per platform.
