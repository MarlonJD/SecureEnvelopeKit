# SecureEnvelopeKit Apple Core Implementation Plan

Date: 2026-06-01

Owner subtree: `packages/SecureEnvelopeKit`

Status: Implemented

## Goal

Implement `SecureEnvelopeKit` as a product-independent Swift Package for iOS and macOS. The first release should provide a small, stable, native-crypto envelope layer for E2EE payload encryption and decryption, with deterministic serialization and a notification-preview-safe hot path.

## Context

The main application will support E2EE notification previews and cross-platform encrypted payload handling. Apple platforms need a reusable package that keeps the envelope protocol separate from app state, notification extensions, message ratchets, storage, and ML-KEM implementation details.

The initial package should prioritize reviewed platform crypto paths:

- AES-256-GCM through CryptoKit for authenticated encryption.
- HKDF-SHA-256 through CryptoKit for key derivation.
- Secure random generation through Security.framework where raw randomness is required.

## Assumptions

- The first implementation is Apple-only and ships as SwiftPM.
- Supported runtime targets start at iOS 15.6 for the app; the package can declare an iOS 15 minimum unless implementation evidence requires a narrower target.
- macOS support should use the same SwiftPM target and CryptoKit-backed implementation.
- ML-KEM-derived shared secrets may feed into the envelope layer as input key material, but ML-KEM itself is not implemented in this package's first milestone.
- Public APIs should not expose app-specific naming, server fields, database models, or notification UI concepts.

## Open Questions

- Exact macOS minimum deployment target for consumers.
- Whether the first release should include semantic version tags immediately or only after the app consumes a local revision.
- Whether envelope fixtures need to be shared with Android and Windows before the first Swift release, or added after the binary format stabilizes.

## Scope

1. Create a SwiftPM package structure.
2. Define a deterministic v1 secure envelope wire format.
3. Implement AES-256-GCM sealing and opening using CryptoKit.
4. Implement HKDF-SHA-256 content-key derivation using CryptoKit.
5. Implement secure random nonce generation using Security.framework-backed randomness.
6. Define typed errors for malformed envelopes, unsupported versions or suites, invalid key material, and authentication failures.
7. Add a notification-preview-safe helper that only parses metadata, authenticates deterministic header bytes as AAD, decrypts a small preview payload, and returns caller-owned display data.
8. Add tests for round trips, tampering, malformed data, deterministic encoding, wrong-key failures, preview behavior, and key derivation determinism.
9. Document security model, non-goals, supported algorithms, and notification hot-path rules.

## Non-Goals

- Implementing ML-KEM, ratchets, double-ratchet state, session setup, or key agreement.
- Performing full message decrypts, history sync, database access, search, or ratchet advancement inside preview helpers.
- Building app notification extensions or platform UI.
- Adding Android or Windows implementations to this repository.
- Designing account recovery, key backup, or server-side envelope storage.
- Adding speculative algorithm agility beyond a clearly versioned and rejected-when-unknown v1 suite identifier.

## Proposed API Shape

The first public surface should stay small:

- `SecureEnvelope`: immutable parsed envelope value.
- `SecureEnvelopeMetadata`: public routing and binding metadata that contains no plaintext secrets.
- `SecureEnvelopeSuite`: supported algorithm suite identifiers.
- `SecureEnvelopeSealer`: `seal(plaintext:keyMaterial:metadata:)`.
- `SecureEnvelopeOpener`: `open(envelope:keyMaterial:)`.
- `SecureEnvelopePreview`: preview-only decrypt helper.
- `SecureEnvelopeError`: typed error cases.

Keep lower-level binary parsing and CryptoKit adapters internal unless tests require `@testable` access.

## Wire Format Rules

- Use a documented binary format with fixed field ordering and explicit length prefixes.
- Include a magic value and version byte.
- Include a suite identifier and key identifier.
- Encode nonce, ciphertext, tag, and public metadata deterministically.
- Use deterministic header bytes as AES-GCM AAD.
- Reject unknown versions, unknown suites, duplicate fields, truncated fields, and trailing undecoded bytes.
- Avoid non-canonical JSON as authenticated data.

## Implementation Steps

1. Bootstrap Package
   - Add `Package.swift`.
   - Add `Sources/SecureEnvelopeKit`.
   - Add `Tests/SecureEnvelopeKitTests`.
   - Configure Apple platforms and a single library product.

2. Model and Errors
   - Add immutable envelope and metadata value types.
   - Add suite/version constants.
   - Add typed errors with no secret-bearing descriptions.

3. Binary Encoding
   - Implement internal encoder and decoder.
   - Add stable fixture tests for a representative envelope.
   - Add malformed input tests for truncation, unsupported version, unsupported suite, and trailing data.

4. Crypto Provider
   - Wrap CryptoKit AES.GCM and HKDF-SHA-256 behind a small internal provider.
   - Generate 96-bit AES-GCM nonces.
   - Use Security.framework-backed randomness for raw random bytes where needed.

5. Seal and Open
   - Implement key derivation with explicit salt and info handling.
   - Use the deterministic header as AAD.
   - Keep ciphertext and tag separate in the envelope model.
   - Ensure authentication failure maps to a typed error without leaking detail.

6. Preview Helper
   - Implement a helper that decrypts only caller-provided preview payload envelopes.
   - Keep it synchronous and dependency-free.
   - Do not call app storage, network, ratchet, sync, or ML-KEM code.

7. Documentation
   - Expand `README.md` with install, quick start, security model, supported algorithms, preview hot path, and non-goals.
   - Add `docs/SECURITY.md` with algorithm choices, threat model boundaries, and operational guidance.

## Verification Gates

- `swift package describe`
- `swift test`
- Manual review that no AES, SHA, HKDF, or RNG primitives are manually implemented.
- Manual review that preview helpers have no database, network, sync, ratchet, or ML-KEM dependencies.
- Manual review that public docs do not include product-specific names.

## Risks

- Wire format changes after app adoption could require migration or fixture updates.
- Metadata mistakes can leak information even if payload encryption is correct.
- CryptoKit availability and deployment target choices should be verified on the app's supported Apple OS matrix.
- Cross-platform compatibility requires binary fixtures to be shared with Android and Windows later.

## Rollback And Recovery

If implementation introduces API or wire-format mistakes before adoption, replace the package revision and avoid tagging a release. If a tagged release has shipped, keep the old decoder tests and introduce a new versioned envelope format instead of silently changing v1 semantics.

## Affected Files

- `Package.swift`
- `Sources/SecureEnvelopeKit/**`
- `Tests/SecureEnvelopeKitTests/**`
- `README.md`
- `docs/SECURITY.md`
- `docs/plans/2026-06-01-secure-envelope-kit-apple-core-plan.md`

## Execution Prompt

```text
Use $google-eng-practices and implement the plan in docs/plans/2026-06-01-secure-envelope-kit-apple-core-plan.md.

You are working in the SecureEnvelopeKit repository. Build the first Apple-only SwiftPM implementation of SecureEnvelopeKit as described in the plan:
- Add Package.swift, Sources/SecureEnvelopeKit, and Tests/SecureEnvelopeKitTests.
- Use CryptoKit AES-256-GCM for authenticated encryption.
- Use CryptoKit HKDF with SHA-256 for content-key derivation.
- Use Security.framework-backed secure randomness where random bytes are needed.
- Do not manually implement AES, SHA, HKDF, or RNG primitives.
- Keep ML-KEM, ratchets, database access, history sync, full message decrypt, and notification UI out of scope.
- Implement deterministic binary envelope encoding with fixed field ordering and length prefixes.
- Use deterministic envelope header bytes as AES-GCM AAD.
- Add a small notification-preview-safe helper that only parses metadata, authenticates AAD, decrypts the preview payload, and returns caller-owned display data.
- Add focused tests for round trip, wrong key, tampered header/AAD, tampered ciphertext, tampered tag, malformed envelope decode, stable binary encoding, preview helper behavior, and HKDF determinism where practical.
- Update README.md and add docs/SECURITY.md.

Verification:
- Run swift package describe.
- Run swift test.
- Confirm no generated build artifacts are committed.

Commit and push after verification passes.
Use author: marlonjd <burak.karahan@mail.ru>
Use a Conventional Commit message, for example: feat: implement secure envelope core
```
