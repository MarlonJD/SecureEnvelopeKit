# Secure Envelope Authenticated Metadata Hardening Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Date:** 2026-06-05

**Goal:** Harden SecureEnvelopeKit's public metadata trust boundary, Android immutability contract, and preview resource limits without changing the v1 wire bytes.

**Architecture:** Keep the v1 binary format and cryptographic suite unchanged. Tighten public API behavior around mutable byte containers and add preview-only resource budgets before decryption. Treat parsed metadata as an untrusted routing hint until AEAD verification succeeds.

**Tech Stack:** Swift/CryptoKit, Kotlin/JCA, .NET `System.Security.Cryptography`, shared markdown spec and security docs.

---

## Owner Subtree

`packages/SecureEnvelopeKit`

The work is package-local but cross-platform inside this package: Swift, Android/Kotlin, .NET, shared spec, shared security docs, and platform security notes.

## Objective

Address the targeted security review findings:

- Android public `ByteArray` properties should not allow callers to mutate authenticated envelope state after parse or seal.
- Preview helpers should bound untrusted serialized/header/public-metadata bytes as well as plaintext.
- E2EE/security docs should make clear that parsed metadata is authenticated only after a successful open with expected key material.

## Scope

In scope:

- Android/Kotlin defensive-copy hardening for public byte-array surfaces.
- Backward-compatible preview constructor/API additions for Swift, Android, and .NET.
- Tests for mutation resistance and preview resource-budget behavior.
- README/security/spec documentation alignment.

Out of scope:

- Changing the v1 wire format, fixture bytes, HKDF `info`, AES-GCM parameters, salt length, nonce length, or tag length.
- Adding ML-KEM, ratchets, session state, replay windows, transcript signatures, storage, networking, or notification UI.
- Changing caller-supplied key-material ownership or key lookup semantics beyond documenting the metadata trust boundary.
- Branch creation, branch switching, commits, pushes, or PR creation unless the user explicitly asks.

## Assumptions and Open Questions

- The v1 wire contract remains stable; all changes must preserve `fixtures/SecureEnvelopeV1/secure-envelope-v1.json`.
- Existing public preview calls must keep compiling: `SecureEnvelopePreview(maxPlaintextBytes: 64)`, `SecureEnvelopePreview(maxPlaintextBytes = 64)`, and `new SecureEnvelopePreview(maxPlaintextBytes: 64)`.
- Default preview limits should be conservative but not surprising: keep `maxPlaintextBytes = 4096`, add `maxSerializedEnvelopeBytes = 16 * 1024`, and add `maxPublicMetadataBytes = 1024`.
- Open question: whether app-level E2EE docs outside this package also describe notification preview metadata as trusted before decrypt. If they exist in another workspace, update them with the same wording after the package change lands.

## Affected Files or Docs

Modify:

- `platforms/android/secure-envelope-kit/src/main/kotlin/io/github/marlonjd/secureenvelope/SecureEnvelope.kt`
- `platforms/android/secure-envelope-kit/src/test/kotlin/io/github/marlonjd/secureenvelope/SecureEnvelopeTest.kt`
- `platforms/swift/Sources/SecureEnvelopeKit/SecureEnvelopeKit.swift`
- `platforms/swift/Tests/SecureEnvelopeKitTests/SecureEnvelopeKitTests.swift`
- `platforms/dotnet/src/SecureEnvelopeKit/SecureEnvelope.cs`
- `platforms/dotnet/tests/SecureEnvelopeKit.Tests/SecureEnvelopeTests.cs`
- `README.md`
- `platforms/swift/README.md`
- `platforms/android/README.md`
- `platforms/dotnet/README.md`
- `docs/SECURITY.md`
- `docs/spec/secure-envelope-v1.md`
- `platforms/swift/docs/SECURITY.md`
- `platforms/android/docs/SECURITY.md`
- `platforms/dotnet/docs/SECURITY.md`

Already updated in the planning pass:

- `docs/SECURITY.md`
- `docs/spec/secure-envelope-v1.md`
- `platforms/swift/docs/SECURITY.md`
- `platforms/android/docs/SECURITY.md`
- `platforms/dotnet/docs/SECURITY.md`

## Phases and Steps

### Task 1: Android Public Byte-Array Immutability

**Files:**

- Modify: `platforms/android/secure-envelope-kit/src/main/kotlin/io/github/marlonjd/secureenvelope/SecureEnvelope.kt`
- Modify: `platforms/android/secure-envelope-kit/src/test/kotlin/io/github/marlonjd/secureenvelope/SecureEnvelopeTest.kt`

- [ ] **Step 1: Add failing Android mutation tests**

Add this test to `SecureEnvelopeTest`:

```kotlin
@Test
fun publicByteArrayViewsAreDefensiveCopies() {
    val metadata = SecureEnvelopeMetadata(
        keyIdentifier = "key-1".toByteArray(Charsets.UTF_8),
        publicContext = "preview".toByteArray(Charsets.UTF_8),
    )
    val exposedKeyIdentifier = metadata.keyIdentifier
    val exposedPublicContext = metadata.publicContext
    exposedKeyIdentifier[0] = 'X'.code.toByte()
    exposedPublicContext[0] = 'Y'.code.toByte()
    assertArrayEquals("key-1".toByteArray(Charsets.UTF_8), metadata.keyIdentifier)
    assertArrayEquals("preview".toByteArray(Charsets.UTF_8), metadata.publicContext)

    val envelope = deterministicEnvelope()
    val expectedSerialized = envelope.serializedData.copyOf()
    val expectedSalt = envelope.salt.copyOf()
    val expectedNonce = envelope.nonce.copyOf()
    val expectedCiphertext = envelope.ciphertext.copyOf()
    val expectedTag = envelope.tag.copyOf()
    val expectedHeader = envelope.authenticatedHeader.copyOf()

    envelope.serializedData[0] = 0
    envelope.salt[0] = 0
    envelope.nonce[0] = 0
    envelope.ciphertext[0] = 0
    envelope.tag[0] = 0
    envelope.authenticatedHeader[0] = 0

    assertArrayEquals(expectedSerialized, envelope.serializedData)
    assertArrayEquals(expectedSalt, envelope.salt)
    assertArrayEquals(expectedNonce, envelope.nonce)
    assertArrayEquals(expectedCiphertext, envelope.ciphertext)
    assertArrayEquals(expectedTag, envelope.tag)
    assertArrayEquals(expectedHeader, envelope.authenticatedHeader)
    assertArrayEquals(plaintext, SecureEnvelopeOpener().open(envelope, keyMaterial))

    val previewResult = SecureEnvelopePreview(maxPlaintextBytes = 64).open(
        envelope.serializedData,
        keyMaterial,
    )
    val expectedPreview = previewResult.plaintext.copyOf()
    previewResult.plaintext[0] = 0
    assertArrayEquals(expectedPreview, previewResult.plaintext)
}
```

Run: `cd platforms/android && ./gradlew test`

Expected before implementation: this new test fails because public `ByteArray` getters expose mutable internal arrays.

- [ ] **Step 2: Make Android metadata expose copies**

In `SecureEnvelopeMetadata`, replace the stored public arrays with private storage plus defensive public getters:

```kotlin
class SecureEnvelopeMetadata @JvmOverloads constructor(
    keyIdentifier: ByteArray,
    publicContext: ByteArray = ByteArray(0),
) {
    private val keyIdentifierBytes: ByteArray = keyIdentifier.copyOf()
    private val publicContextBytes: ByteArray = publicContext.copyOf()

    val keyIdentifier: ByteArray get() = keyIdentifierBytes.copyOf()
    val publicContext: ByteArray get() = publicContextBytes.copyOf()

    internal val keyIdentifierUnsafe: ByteArray get() = keyIdentifierBytes
    internal val publicContextUnsafe: ByteArray get() = publicContextBytes

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SecureEnvelopeMetadata) return false
        return keyIdentifierBytes.contentEquals(other.keyIdentifierUnsafe) &&
            publicContextBytes.contentEquals(other.publicContextUnsafe)
    }

    override fun hashCode(): Int =
        31 * keyIdentifierBytes.contentHashCode() + publicContextBytes.contentHashCode()
}
```

Update `SecureEnvelopeWireFormat.validateMetadata` and `headerBytes` to use `metadata.keyIdentifierUnsafe` and `metadata.publicContextUnsafe` internally so the encoder does not allocate extra copies.

- [ ] **Step 3: Make Android envelopes and preview results expose copies**

In `SecureEnvelope`, store private byte arrays and return copies from public getters. Keep internal unsafe accessors for crypto and serialization:

```kotlin
class SecureEnvelope private constructor(
    val version: Int,
    val suite: SecureEnvelopeSuite,
    val metadata: SecureEnvelopeMetadata,
    salt: ByteArray,
    nonce: ByteArray,
    ciphertext: ByteArray,
    tag: ByteArray,
    serializedData: ByteArray,
    authenticatedHeader: ByteArray,
) {
    private val saltBytes = salt.copyOf()
    private val nonceBytes = nonce.copyOf()
    private val ciphertextBytes = ciphertext.copyOf()
    private val tagBytes = tag.copyOf()
    private val serializedBytes = serializedData.copyOf()
    private val authenticatedHeaderBytes = authenticatedHeader.copyOf()

    val salt: ByteArray get() = saltBytes.copyOf()
    val nonce: ByteArray get() = nonceBytes.copyOf()
    val ciphertext: ByteArray get() = ciphertextBytes.copyOf()
    val tag: ByteArray get() = tagBytes.copyOf()
    val serializedData: ByteArray get() = serializedBytes.copyOf()
    internal val authenticatedHeader: ByteArray get() = authenticatedHeaderBytes.copyOf()

    internal val saltUnsafe: ByteArray get() = saltBytes
    internal val nonceUnsafe: ByteArray get() = nonceBytes
    internal val ciphertextUnsafe: ByteArray get() = ciphertextBytes
    internal val tagUnsafe: ByteArray get() = tagBytes
    internal val serializedDataUnsafe: ByteArray get() = serializedBytes
    internal val authenticatedHeaderUnsafe: ByteArray get() = authenticatedHeaderBytes

    // Keep the existing companion object below this storage block.
}
```

Update internal callers:

- `SecureEnvelope.parse`: compare `envelope.serializedDataUnsafe` with input.
- `SecureEnvelopeOpener.open`: use `saltUnsafe`, `nonceUnsafe`, `ciphertextUnsafe`, `tagUnsafe`, and `authenticatedHeaderUnsafe`.
- `SecureEnvelopeWireFormat.decode`: compare `envelope.authenticatedHeaderUnsafe.size` to `headerLength`.

In `SecureEnvelopePreviewResult`, expose a defensive plaintext copy:

```kotlin
class SecureEnvelopePreviewResult internal constructor(
    val metadata: SecureEnvelopeMetadata,
    plaintext: ByteArray,
) {
    private val plaintextBytes: ByteArray = plaintext.copyOf()
    val plaintext: ByteArray get() = plaintextBytes.copyOf()
}
```

- [ ] **Step 4: Run Android tests**

Run: `cd platforms/android && ./gradlew test`

Expected: PASS, including the new mutation test.

### Task 2: Preview Resource Budgets on All Platforms

**Files:**

- Modify: `platforms/swift/Sources/SecureEnvelopeKit/SecureEnvelopeKit.swift`
- Modify: `platforms/swift/Tests/SecureEnvelopeKitTests/SecureEnvelopeKitTests.swift`
- Modify: `platforms/android/secure-envelope-kit/src/main/kotlin/io/github/marlonjd/secureenvelope/SecureEnvelope.kt`
- Modify: `platforms/android/secure-envelope-kit/src/test/kotlin/io/github/marlonjd/secureenvelope/SecureEnvelopeTest.kt`
- Modify: `platforms/dotnet/src/SecureEnvelopeKit/SecureEnvelope.cs`
- Modify: `platforms/dotnet/tests/SecureEnvelopeKit.Tests/SecureEnvelopeTests.cs`

- [ ] **Step 1: Add Swift preview budget tests**

Add to `SecureEnvelopeKitTests`:

```swift
func testPreviewHelperRejectsOversizedSerializedEnvelopeBeforeParse() throws {
    let envelope = try deterministicEnvelope()
    let preview = SecureEnvelopePreview(
        maxPlaintextBytes: 64,
        maxSerializedEnvelopeBytes: envelope.serializedData.count - 1
    )

    XCTAssertThrowsSecureEnvelopeError(.previewPayloadTooLarge) {
        _ = try preview.open(serializedData: envelope.serializedData, keyMaterial: wrongKeyMaterial)
    }
}

func testPreviewHelperRejectsOversizedPublicMetadataBeforeOpen() throws {
    let preview = SecureEnvelopePreview(
        maxPlaintextBytes: 64,
        maxSerializedEnvelopeBytes: 4096,
        maxPublicMetadataBytes: 4
    )
    let envelope = try deterministicEnvelope()

    XCTAssertThrowsSecureEnvelopeError(.previewPayloadTooLarge) {
        _ = try preview.open(serializedData: envelope.serializedData, keyMaterial: wrongKeyMaterial)
    }
}
```

Expected before implementation: these tests do not compile because the constructor lacks the new parameters.

- [ ] **Step 2: Implement Swift preview budgets**

Replace `SecureEnvelopePreview` with:

```swift
public struct SecureEnvelopePreview {
    public let maxPlaintextBytes: Int
    public let maxSerializedEnvelopeBytes: Int
    public let maxPublicMetadataBytes: Int

    public init(
        maxPlaintextBytes: Int = 4096,
        maxSerializedEnvelopeBytes: Int = 16 * 1024,
        maxPublicMetadataBytes: Int = 1024
    ) {
        self.maxPlaintextBytes = maxPlaintextBytes
        self.maxSerializedEnvelopeBytes = maxSerializedEnvelopeBytes
        self.maxPublicMetadataBytes = maxPublicMetadataBytes
    }

    public func open(serializedData: Data, keyMaterial: Data) throws -> SecureEnvelopePreviewResult {
        guard maxSerializedEnvelopeBytes >= 0,
              serializedData.count <= maxSerializedEnvelopeBytes else {
            throw SecureEnvelopeError.previewPayloadTooLarge
        }

        let envelope = try SecureEnvelope(serializedData: serializedData)
        guard maxPublicMetadataBytes >= 0,
              envelope.metadata.keyIdentifier.count + envelope.metadata.publicContext.count <= maxPublicMetadataBytes,
              maxPlaintextBytes >= 0,
              envelope.ciphertext.count <= maxPlaintextBytes else {
            throw SecureEnvelopeError.previewPayloadTooLarge
        }

        let plaintext = try SecureEnvelopeOpener().open(envelope: envelope, keyMaterial: keyMaterial)
        guard plaintext.count <= maxPlaintextBytes else {
            throw SecureEnvelopeError.previewPayloadTooLarge
        }

        return SecureEnvelopePreviewResult(metadata: envelope.metadata, plaintext: plaintext)
    }
}
```

Run: `cd platforms/swift && swift test`

Expected: PASS.

- [ ] **Step 3: Add Android preview budget tests**

Add to `SecureEnvelopeTest`:

```kotlin
@Test
fun previewHelperRejectsOversizedSerializedEnvelopeBeforeParse() {
    val envelope = deterministicEnvelope()
    val preview = SecureEnvelopePreview(
        maxPlaintextBytes = 64,
        maxSerializedEnvelopeBytes = envelope.serializedData.size - 1,
    )

    assertEnvelopeError<SecureEnvelopeException.PreviewPayloadTooLarge> {
        preview.open(envelope.serializedData, wrongKeyMaterial)
    }
}

@Test
fun previewHelperRejectsOversizedPublicMetadataBeforeOpen() {
    val envelope = deterministicEnvelope()
    val preview = SecureEnvelopePreview(
        maxPlaintextBytes = 64,
        maxSerializedEnvelopeBytes = 4096,
        maxPublicMetadataBytes = 4,
    )

    assertEnvelopeError<SecureEnvelopeException.PreviewPayloadTooLarge> {
        preview.open(envelope.serializedData, wrongKeyMaterial)
    }
}
```

- [ ] **Step 4: Implement Android preview budgets**

Update the constructor and `open` method:

```kotlin
class SecureEnvelopePreview @JvmOverloads constructor(
    val maxPlaintextBytes: Int = 4096,
    val maxSerializedEnvelopeBytes: Int = 16 * 1024,
    val maxPublicMetadataBytes: Int = 1024,
) {
    fun open(serializedData: ByteArray, keyMaterial: ByteArray): SecureEnvelopePreviewResult {
        if (maxSerializedEnvelopeBytes < 0 || serializedData.size > maxSerializedEnvelopeBytes) {
            throw SecureEnvelopeException.PreviewPayloadTooLarge()
        }

        val envelope = SecureEnvelope.parse(serializedData)
        val metadataByteCount =
            envelope.metadata.keyIdentifierUnsafe.size + envelope.metadata.publicContextUnsafe.size
        if (maxPublicMetadataBytes < 0 ||
            metadataByteCount > maxPublicMetadataBytes ||
            maxPlaintextBytes < 0 ||
            envelope.ciphertextUnsafe.size > maxPlaintextBytes
        ) {
            throw SecureEnvelopeException.PreviewPayloadTooLarge()
        }

        val plaintext = SecureEnvelopeOpener().open(envelope, keyMaterial)
        if (plaintext.size > maxPlaintextBytes) {
            throw SecureEnvelopeException.PreviewPayloadTooLarge()
        }
        return SecureEnvelopePreviewResult(metadata = envelope.metadata, plaintext = plaintext)
    }
}
```

Run: `cd platforms/android && ./gradlew test`

Expected: PASS.

- [ ] **Step 5: Add .NET preview budget tests**

Add to `SecureEnvelopeTests`:

```csharp
[Fact]
public void PreviewHelperRejectsOversizedSerializedEnvelopeBeforeParse()
{
    var envelope = DeterministicEnvelope();
    var preview = new SecureEnvelopePreview(
        maxPlaintextBytes: 64,
        maxSerializedEnvelopeBytes: envelope.SerializedData.Length - 1);

    AssertEnvelopeError(SecureEnvelopeError.PreviewPayloadTooLarge, () =>
        preview.Open(envelope.SerializedData.Span, WrongKeyMaterial));
}

[Fact]
public void PreviewHelperRejectsOversizedPublicMetadataBeforeOpen()
{
    var envelope = DeterministicEnvelope();
    var preview = new SecureEnvelopePreview(
        maxPlaintextBytes: 64,
        maxSerializedEnvelopeBytes: 4096,
        maxPublicMetadataBytes: 4);

    AssertEnvelopeError(SecureEnvelopeError.PreviewPayloadTooLarge, () =>
        preview.Open(envelope.SerializedData.Span, WrongKeyMaterial));
}
```

- [ ] **Step 6: Implement .NET preview budgets**

Replace the preview constructor and open checks with:

```csharp
public sealed class SecureEnvelopePreview
{
    public SecureEnvelopePreview(
        int maxPlaintextBytes = 4096,
        int maxSerializedEnvelopeBytes = 16 * 1024,
        int maxPublicMetadataBytes = 1024)
    {
        MaxPlaintextBytes = maxPlaintextBytes;
        MaxSerializedEnvelopeBytes = maxSerializedEnvelopeBytes;
        MaxPublicMetadataBytes = maxPublicMetadataBytes;
    }

    public int MaxPlaintextBytes { get; }
    public int MaxSerializedEnvelopeBytes { get; }
    public int MaxPublicMetadataBytes { get; }

    public SecureEnvelopePreviewResult Open(ReadOnlySpan<byte> serializedData, ReadOnlySpan<byte> keyMaterial)
    {
        if (MaxSerializedEnvelopeBytes < 0 || serializedData.Length > MaxSerializedEnvelopeBytes)
        {
            throw SecureEnvelopeException.PreviewPayloadTooLarge();
        }

        var envelope = SecureEnvelope.Parse(serializedData);
        var metadataByteCount = envelope.Metadata.KeyIdentifier.Length + envelope.Metadata.PublicContext.Length;
        if (MaxPublicMetadataBytes < 0 ||
            metadataByteCount > MaxPublicMetadataBytes ||
            MaxPlaintextBytes < 0 ||
            envelope.Ciphertext.Length > MaxPlaintextBytes)
        {
            throw SecureEnvelopeException.PreviewPayloadTooLarge();
        }

        var plaintext = new SecureEnvelopeOpener().Open(envelope, keyMaterial);
        if (plaintext.Length > MaxPlaintextBytes)
        {
            throw SecureEnvelopeException.PreviewPayloadTooLarge();
        }

        return new SecureEnvelopePreviewResult(envelope.Metadata, plaintext);
    }
}
```

Run: `cd platforms/dotnet && dotnet test`

Expected: PASS.

### Task 3: Documentation and API Contract Alignment

**Files:**

- Modify: `README.md`
- Modify: `platforms/swift/README.md`
- Modify: `platforms/android/README.md`
- Modify: `platforms/dotnet/README.md`
- Review: `docs/SECURITY.md`
- Review: `docs/spec/secure-envelope-v1.md`
- Review: `platforms/swift/docs/SECURITY.md`
- Review: `platforms/android/docs/SECURITY.md`
- Review: `platforms/dotnet/docs/SECURITY.md`

- [ ] **Step 1: Document preview constructor budgets in platform READMEs**

Update each platform README preview section to name the three limits:

```text
Preview helpers bound the serialized envelope, public metadata, and plaintext
display payload. Parsed metadata is a routing hint until AEAD verification
succeeds with the expected key material.
```

Use platform-specific parameter names:

- Swift: `maxPlaintextBytes`, `maxSerializedEnvelopeBytes`, `maxPublicMetadataBytes`
- Android: `maxPlaintextBytes`, `maxSerializedEnvelopeBytes`, `maxPublicMetadataBytes`
- .NET: `maxPlaintextBytes`, `maxSerializedEnvelopeBytes`, `maxPublicMetadataBytes`

- [ ] **Step 2: Re-check shared E2EE/security docs**

Confirm these statements remain present:

- `docs/SECURITY.md`: parsed metadata is untrusted until successful open.
- `docs/spec/secure-envelope-v1.md`: parsers may expose `key_identifier` before authentication for key lookup only.
- Platform `docs/SECURITY.md`: preview callers should bound serialized/header/public metadata sizes.

- [ ] **Step 3: Keep fixture stable**

Run the platform fixture parity tests through the normal test commands. The shared fixture file must not change.

## Verification Gates

Run all of the following from `packages/SecureEnvelopeKit` or the listed platform folders:

```bash
cd platforms/swift
swift test
```

```bash
cd platforms/android
./gradlew test
```

```bash
cd platforms/dotnet
dotnet test
```

Also run:

```bash
git diff -- fixtures/SecureEnvelopeV1/secure-envelope-v1.json
```

Expected: no diff for the fixture.

## Risks and Mitigations

- Risk: Android defensive-copy changes add allocations. Mitigation: keep unsafe internal accessors for crypto and serialization paths; copy only at public API boundaries.
- Risk: New preview defaults reject unusually large public metadata. Mitigation: constructor parameters are caller-tunable and do not change the v1 wire format.
- Risk: Metadata trust-boundary docs could be misunderstood as key lookup being forbidden. Mitigation: explicitly allow using `key_identifier` as a candidate-key routing hint before authentication, but forbid treating it as trusted authorization.
- Risk: Cross-platform API drift. Mitigation: add equivalent tests and README notes for Swift, Android, and .NET in the same change.

## Dependencies and Ownership Boundaries

- This package depends on platform crypto providers only; no app E2EE session layer is introduced.
- The higher-level E2EE client/session layer still owns key agreement, ratchets, skipped-message keys, replay windows, roster verification, transcript signatures, and full-message decrypt.
- Notification preview surfaces may use this package only for bounded preview envelopes; they must not call storage, networking, ratchets, ML-KEM, or app UI renderers through this package.

## Rollback or Recovery Notes

- If preview budget additions create source compatibility issues, keep the new checks but preserve old constructor overloads/signatures with defaults.
- If Android allocation overhead is unacceptable, keep defensive public getters and optimize only internal call sites with unsafe accessors; do not return mutable internal arrays from public API.
- If any fixture parity test changes `envelopeHex`, `authenticatedHeaderHex`, `derivedContentKeyHex`, `ciphertextHex`, or `tagHex`, stop and revert the implementation change that modified wire semantics.

## Execution Prompt

```text
Implement the plan at packages/SecureEnvelopeKit/docs/plans/2026-06-05-secure-envelope-authenticated-metadata-hardening-plan.md.

Use repository task-routing and verification-gate guidance, plus Codex Security/fix-finding posture for the previously identified SecureEnvelopeKit findings. Work in the current branch; do not create, switch, rename, or delete branches. Do not commit, push, or open a PR unless I explicitly ask after verification.

Read the package guidance from AGENTS.md and the package docs already touched by the plan: docs/SECURITY.md, docs/spec/secure-envelope-v1.md, platforms/swift/docs/SECURITY.md, platforms/android/docs/SECURITY.md, and platforms/dotnet/docs/SECURITY.md.

Implement the plan task-by-task:
1. Harden Android public ByteArray API surfaces with defensive public getters and internal unsafe accessors, then add mutation-resistance tests.
2. Add preview resource budgets on Swift, Android, and .NET: maxPlaintextBytes, maxSerializedEnvelopeBytes, and maxPublicMetadataBytes, with tests that reject oversized serialized envelopes and public metadata before AEAD open.
3. Update README/API docs so preview limits and the parsed-metadata trust boundary are clear.

Verify with:
- cd platforms/swift && swift test
- cd platforms/android && ./gradlew test
- cd platforms/dotnet && dotnet test
- git diff -- fixtures/SecureEnvelopeV1/secure-envelope-v1.json

Report the changed files, test results, and any remaining E2EE documentation gaps. Keep the v1 fixture and wire bytes unchanged.
```
