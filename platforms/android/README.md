# SecureEnvelopeKit (Android / Kotlin)

Product-independent secure envelope protocol kit — the Android/JVM
implementation. This is one platform of the
[SecureEnvelopeKit monorepo](../../README.md); the language-neutral contract and
shared fixture live at the repository root under
[`docs/spec/`](../../docs/spec/secure-envelope-v1.md) and
[`fixtures/`](../../fixtures/SecureEnvelopeV1/secure-envelope-v1.json).

## Overview

`secure-envelope-kit` is a Kotlin library that seals caller-provided payloads
into a deterministic, versioned binary envelope using AES-256-GCM with an
HKDF-SHA-256 content key, and opens them again. It conforms byte-for-byte to the
shared v1 wire format, so envelopes interoperate with the Swift and .NET
implementations.

It is intentionally product-independent: it knows nothing about app state,
accounts, databases, notification UI, networking, ratchets, ML-KEM, or message
history. The caller supplies input key material.

### Why a Kotlin/JVM library

The envelope core depends only on the JVM's JCA crypto providers
(`javax.crypto` / `java.security`), which are present identically on Android.
It has no Android-framework dependency (no `Context`, Keystore, storage,
networking, or ML-KEM), so it ships as a plain Kotlin/JVM library that Android
apps consume as a normal dependency and that tests run on the JVM. Android
Keystore or other storage adapters, if ever needed, belong in a separate
optional module, not in this core.

## Build and test

From this directory:

```sh
./gradlew test
```

Tests run as JVM unit tests (JUnit 4). They include round-trip, wrong-key,
tampered header/ciphertext/tag, malformed decode, stable encoding, preview
behavior, HKDF determinism, an RFC 5869 HKDF-SHA-256 vector, and cross-platform
parity against the shared Swift fixture (reproducing the bytes and opening the
committed envelope).

Requirements: a JDK 17+ (for example the JBR bundled with Android Studio). Set
`JAVA_HOME` accordingly if `gradlew` cannot find a JDK.

## Quick start

```kotlin
import io.github.marlonjd.secureenvelope.*

val keyMaterial = ByteArray(32) { 0x42 } // >= 32 bytes from your key agreement / ratchet
val metadata = SecureEnvelopeMetadata(
    keyIdentifier = "recipient-key-v1".toByteArray(),
    publicContext = "preview".toByteArray(),
)

val envelope = SecureEnvelopeSealer().seal(
    plaintext = "hello".toByteArray(),
    keyMaterial = keyMaterial,
    metadata = metadata,
)

val bytes = envelope.serializedData                 // canonical wire bytes
val plaintext = SecureEnvelopeOpener().open(bytes, keyMaterial)
```

For notification-style previews:

```kotlin
val preview = SecureEnvelopePreview(maxPlaintextBytes = 4096)
val result = preview.open(bytes, keyMaterial)        // result.metadata, result.plaintext
```

## Algorithms

`SecureEnvelopeSuite.V1_AES_256_GCM_HKDF_SHA256` uses:

- AES-256-GCM via `javax.crypto.Cipher("AES/GCM/NoPadding")` (12-byte nonce,
  16-byte tag).
- HKDF-SHA-256 (RFC 5869) built over `javax.crypto.Mac("HmacSHA256")`.
- A 32-byte random salt and 12-byte random nonce from `java.security.SecureRandom`.

The library does not implement AES, SHA-256, HMAC internals, GCM, HKDF, or RNG
by hand.

## Wire format and security

The binary format, AAD rules, and rejection behavior are specified in
[`docs/spec/secure-envelope-v1.md`](../../docs/spec/secure-envelope-v1.md).
Platform security notes are in [`docs/SECURITY.md`](docs/SECURITY.md); the shared
model is in [`../../docs/SECURITY.md`](../../docs/SECURITY.md).

## Non-goals

No ML-KEM or key agreement, ratchets, sessions, databases, networking, history
sync, full-message decrypt pipelines, notification UI, account recovery, or
server-side storage. There is no separate `SecureEnvelopeKotlin` repository; this
is the Android platform of the single SecureEnvelopeKit repository.
