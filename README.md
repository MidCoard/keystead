# Keystead Core

Keystead Core is a Java 25 library for building encrypted password and secret
vaults. It owns the parts of Keystead that must remain independent of a user
interface or synchronization server: key derivation, authenticated encryption,
typed secret schemas, local persistence, backup, synchronization records,
device provisioning, and key rotation.

This repository is intended for application developers, security reviewers,
and contributors. It is not the desktop application and it does not run a
server. The separately maintained Keystead Client uses this library; Keystead
Server stores and coordinates the opaque encrypted data produced by clients.

## Why Keystead Core exists

A password manager is more than a map of names to encrypted strings. It needs a
stable record model, explicit revision semantics, safe deletion propagation,
recoverable writes, key lifecycle rules, and APIs that avoid turning plaintext
into long-lived application state.

Keystead Core makes those rules part of the library instead of leaving every
client to invent them. Its design goals are:

- keep secret payloads encrypted at rest and outside narrowly scoped callbacks;
- make record and key state transitions explicit and testable;
- keep the synchronization server outside the decryption boundary;
- represent different credential types with canonical schemas;
- fail closed on unsupported algorithms, malformed rows, revision regressions,
  and incomplete device packages;
- preserve compatibility through versioned vault headers, records, and backup
  formats.

## Architecture

```mermaid
flowchart LR
    App["Application or Keystead Client"] --> API["VaultService / VaultHandle"]
    API --> Schema["Typed drafts, views, and schema validation"]
    API --> Crypto["Key derivation and authenticated encryption"]
    API --> Sync["Encrypted sync and backup codecs"]
    Crypto --> Store["VaultStore"]
    Schema --> Store
    Sync --> Store
    Store --> File["FileVaultStore"]
    Sync --> Server["Optional zero-knowledge server"]
```

The boundaries have different responsibilities:

| Boundary | Responsibility |
| --- | --- |
| `VaultService` | Creates, opens, provisions, and rotates vaults. |
| `VaultHandle` | Performs typed secret operations while an unlocked vault key is alive. |
| Drafts and views | Expose plaintext through caller-controlled, short-lived callbacks. |
| `DefaultCryptoService` | Derives and wraps keys, encrypts payloads, and processes device key packages. |
| `VaultStore` | Defines durable vault-header, record, tombstone, and rotation operations. |
| Sync and backup codecs | Move encrypted rows without decrypting their secret payloads. |

`FileVaultStore` is the included filesystem implementation. The `VaultStore`
interface is deliberately separate so applications can supply another durable
store without replacing the cryptographic or record model.

## How a vault operation works

1. A master password derives a wrapping key using the KDF parameters stored in
   the vault header. The derived key unwraps a random vault key; it is not used
   directly as the record-encryption key.
2. `VaultHandle` keeps the unwrapped vault key only for the lifetime of the
   handle. Closing the handle destroys its owned key material.
3. A typed draft validates metadata and required fields against the canonical
   `SecretTypeSchema`.
4. The secret payload is encoded and encrypted with authenticated encryption.
   Vault ID, record metadata, and revision are encoded as authenticated data so
   rows cannot be silently moved or relabeled.
5. The store commits the encrypted record and its monotonic revision. Deletes
   become tombstones so another device can learn that a record was removed.
6. Reads decrypt inside a typed view callback. The caller decides how briefly
   to expose copied character or byte arrays.

The server, if used, receives encrypted profiles, encrypted envelopes, revision
data, tombstones, and wrapped vault-key packages. It does not receive the vault
key or plaintext secret fields.

## Capabilities

### Vault and record lifecycle

- Create and open password-protected vaults.
- Provision a vault from a device-wrapped vault-key package.
- Add, update, list, reveal, and delete typed secrets.
- Rotate the vault key and re-encrypt current records.
- Reject stale revisions and report import conflicts rather than silently
  replacing newer local state.

### Generators

- Configurable passwords and API tokens.
- Ed25519 and RSA SSH key material.
- RSA-first OpenPGP key pairs.
- MFA seeds and `otpauth` URIs.
- X.509 certificate/private-key bundles.

Generated private material is owned by `SecretBuffer`-based or
`AutoCloseable` values so callers can deterministically destroy it.

### Data movement

- Deterministic encrypted export ordered by revision and secret ID.
- Tombstone propagation and structured sync conflict reports.
- Versioned encrypted backup archives with manifest and entry integrity checks.
- Safe restore that rejects a conflicting existing vault header before writing.
- Device-specific wrapped vault-key packages for zero-knowledge provisioning.

### Recovery and collaborative key lifecycle

- Offline recovery-kit material whose account credential and recovery private
  key are derived and encrypted on the client side.
- Recovery-bound vault-key packages that let a valid kit rewrap the current
  vault key without disclosing it to a server.
- Canonical verified-device recovery requests that can be signed by an
  existing trusted device.
- Prepared vault-key rotations that generate the next key without changing
  the live vault until all required recipient packages are ready.
- Restart-safe resumption from a device-wrapped staged package, followed by an
  atomic local commit.

## Secret type model

Keystead does not treat every item as an arbitrary collection of strings.
`SecretTypeCatalog` is the source of truth for field names, sensitivity,
required fields, reveal eligibility, import aliases, export names, optional
length limits, taxonomy defaults, and custom-field policy.

The current vocabulary is:

| Type | Typical protected fields |
| --- | --- |
| `LOGIN_PASSWORD` | Username, password, URL, and notes |
| `SECURE_NOTE` | Note body |
| `SSH_KEY` | Private key, public key, passphrase, and comment |
| `API_TOKEN` | Token, endpoint, and account context |
| `GPG_KEY` | Private key, public key, passphrase, and identity |
| `MFA_SECRET` | Seed and `otpauth` URI |
| `CERTIFICATE` | Certificate, private key, and passphrase |
| `GENERIC_SECRET` | Schema-permitted custom secret fields |

Strict types reject unknown or incomplete field shapes. This gives importers,
exporters, desktop forms, and protocol clients one effective vocabulary.

## Cryptography and key lifecycle

The default configuration uses PBKDF2-HMAC-SHA-256 with 120,000 iterations to
wrap a random vault key and AES-256-GCM for secret payloads. The algorithm
registry also recognizes PBKDF2-HMAC-SHA-512 and ChaCha20-Poly1305 for compatible
rows. Device wrapping uses an approved Tink ECIES P-256 package format.

These are format and implementation choices, not a claim that one fixed KDF
cost is ideal for every deployment. Applications should treat algorithm
registry changes and KDF upgrades as migrations, benchmark parameters for their
target hardware, and retain compatibility tests for existing vaults. A new
password KDF requires an explicitly registered `PasswordKeyDerivation`
provider, canonical parameters in the vault header, and migration and
compatibility tests for both existing and new headers. Unknown algorithms and
unsupported parameters fail closed; Core does not fall back to another KDF.

Key material is represented by owned objects such as `VaultKey`,
`DeviceKeyPair`, and `SecretBuffer`. They copy caller data at boundaries,
redact `toString()`, reject use after destruction, and wipe owned arrays when
closed. `SecretBuffer` is a provider-backed facade over `SecretMemoryProvider`.
The convenience default is `SecretMemoryProvider.systemDefault()`, which returns
the fail-closed `NativeLockedSecretMemoryProvider`: secret bytes are copied into
a page-locked native buffer, and a missing native prerequisite
raises `NativeMemoryUnavailableException` rather than silently falling back to
heap memory. Applications that must tolerate the absence of native access can
explicitly downgrade with `SecretMemoryProvider.heap()`, which keeps a wiped
heap array, and every convenience type retains an overload that accepts an
explicit provider. See
[Native memory and process hardening](#native-memory-and-process-hardening)
for the lifecycle, per-platform backends, and deployment responsibilities.

Wiping and page locking reduce the lifetime and exposure of Keystead-owned
copies, but they are not a guarantee of perfect erasure or full live-memory
resistance. Locking prevents locked pages from being paged to disk and dump
exclusion removes them from core dumps on supported platforms; neither defeats
a debugger, an injected agent, a privileged process reader, copying garbage
collection, JIT or native temporaries, or a copy owned by a cryptographic or
memory provider.

Recovery-kit material follows the same ownership model. New code should use
`RecoveryKitCodec.encodeSecret(RecoveryKit)` and
`RecoveryKitCodec.decode(SecretBuffer)` so the complete encoded kit remains in
mutable, closeable storage. The compatibility `String` encoder and decoder are
deprecated because an immutable secret `String` remains visible in JVM heap
dumps and cannot be wiped deterministically.
The deprecated `DeviceKeyPair.privateKey()` accessor is retained for source
compatibility and returns a caller-wiped heap array; new code should prefer
`copyPrivateKey(Consumer<byte[]>)`.

Core enforces resource ceilings at untrusted file, envelope, package, sync, and
KDF boundaries:

| Input | Maximum |
| --- | ---: |
| Stored properties file | 1,048,576 bytes |
| Encrypted-envelope ciphertext | 1,048,576 bytes |
| Encrypted-envelope authenticated data (AAD) | 65,536 bytes |
| Encoded sync profile | 2,097,152 characters |
| Encoded sync envelope | 2,097,152 characters |
| Wrapped device or recovery vault-key package | 1,048,576 bytes |
| Password-KDF salt | 64 bytes |
| PBKDF2 iterations | 10,000,000 |
| Canonical KDF parameters | 16 entries; printable ASCII names of at most 64 characters; positive integer values no greater than `Integer.MAX_VALUE` |

The 1 MiB envelope limit remains available to non-file formats. The properties
file store additionally rejects any model-valid value whose serialized Base64
properties representation would exceed its 1 MiB stored-file limit, before
replacing an existing file.

## Native memory and process hardening

Keystead Core uses the Java 25 Foreign Function and Memory API to keep secret
material in locked native memory and to expose strict, process-wide hardening.
The public contracts live in `top.focess.keystead.memory` and
`top.focess.keystead.security`; FFM segments, addresses, and raw causes never
leave the internal packages.

`SecretMemoryProvider.systemDefault()` (alias `nativeLocked()`) returns the
fail-closed `NativeLockedSecretMemoryProvider`. `protect(byte[])` copies the
value into a page-locked native buffer owned by a shared
`Arena`; a missing prerequisite raises `NativeMemoryUnavailableException`
instead of falling back to heap memory. `SecretMemoryProvider.heap()` is the
explicit downgrade for deployments without native access, and every convenience
type retains an overload that accepts an explicit provider.

Native protection is bounded and lifecycle-closed. `NativeSecretMemory` runs an
`ALLOCATED -> LOCKED -> DUMP_EXCLUDED -> COPY_STARTED -> LIVE` state machine:
allocation, locking, and (on Linux) dump exclusion are verified before the
buffer is live, a one-pass volatile wipe and unlock run on close, and an
owner-free `Cleaner` releases the page if an owner is abandoned. Quota
exhaustion does not reopen access to a closed buffer.
`NativeMemoryProtection.inspect()` performs a one-page
allocate/lock/dump-exclude/wipe/unlock/release probe without retaining the page
and returns a redacted `NativeMemoryProtectionReport` with one entry per
`NativeProtectionControl` in enum order; capability failure is report data and
never throws.

The backends share a reviewed ABI layer and capture `errno` or the Windows last
error into redacted results:

| Platform | Memory backend | Process hardening |
| --- | --- | --- |
| Windows x86-64 | Kernel32 `VirtualAlloc`/`VirtualLock`/`VirtualUnlock`/`VirtualFree` | OS debugger isolation is `APPLICATION_REQUIRED` |
| Linux x86-64/AArch64 | libc `mmap`/`mlock`/`munmap` with `madvise(MADV_DONTDUMP)` | `prctl(PR_SET_DUMPABLE)` and `setrlimit(RLIMIT_CORE)` |
| macOS x86-64/AArch64 | libc `mmap`/`mlock`/`munlock` | `setrlimit(RLIMIT_CORE)` |

`ProcessHardening.inspect()` returns a redacted `ProcessHardeningReport`
snapshot of the applicable controls without mutating, so it never reports
`HardeningStatus.ENFORCED`. `ProcessHardening.applyStrict()` is serialized,
monotonic, idempotent, and non-transactional: it completes every immutable
prerequisite preflight before mutating, then sets and verifies dumpability and
the core limit on Linux and the core limit on macOS. Deployment
responsibilities Core cannot safely enforce are reported as
`HardeningStatus.APPLICATION_REQUIRED`. The hard `RLIMIT_CORE` limit is lowered
irreversibly for an unprivileged process, so `applyStrict()` is intended to run
in an expendable child JVM rather than a long-lived host process; `inspect()`
is the non-mutating entry point.

Consuming applications must grant native access to the Core module:
`--enable-native-access=top.focess.keystead.core` on the module path, or
`--enable-native-access=ALL-UNNAMED` on the classpath. Under
`--illegal-native-access=deny` or without the grant, the native provider fails
closed. On Linux, `mlock` is bounded by `RLIMIT_MEMLOCK` and `CAP_IPC_LOCK`;
deployments that want locked secret memory should raise the memlock limit or
grant the capability. Locked memory and dump exclusion are bounded in-memory
guarantees: they reduce paging and core-dump exposure, not resistance to a
live-memory attacker with process control.

## Synchronization model

Synchronization operates on encrypted rows, not decrypted secrets.

- Revisions are positive and monotonic within a vault.
- Exports are stable by revision and secret ID.
- A delete produces a tombstone with no encrypted payload fields.
- Importing a newer tombstone removes the local active record.
- An older remote row cannot overwrite newer local state; conflicts are
  returned in `SyncImportReport`.
- Mixed-vault imports are rejected before any row is written.
- Server pagination advances through explicit revision cursors.

Automatic tombstone compaction is intentionally not implemented. The server
can record device pull acknowledgements and evaluate conservative eligibility,
but deleting tombstones automatically would require stronger retention and
device-acknowledgement guarantees.

## Backup and crash recovery

`BackupArchiveCodec` writes encrypted, versioned archives. Entry digests detect
corruption; they do not add secrecy beyond the encrypted payload. The reader
returns structured unsupported/corrupt-entry information where possible, and
restore reports skipped or conflicting rows.

`FileVaultStore` uses atomic replacement for durable files. Vault-key rotation
uses a journal because it changes the header, active records, and tombstones as
one logical operation. Startup recovery examines the journal and completes or
rolls back the interrupted transition. Crash-injection tests cover failures at
the journal and replacement boundaries.

## Security model and threat boundaries

Keystead Core is designed to protect a vault when encrypted files or the sync
database are copied by an attacker who does not possess the master password,
device private key, or unlocked vault key.

It does not protect against:

- malware or a debugger controlling the process while the vault is unlocked;
- a compromised client that captures plaintext before encryption;
- weak master passwords or poorly chosen deployment-specific KDF parameters;
- loss of every password, device key, and backup;
- malicious changes to the library binary or its dependencies;
- sensitive local listing metadata being observed by an attacker with access
  to the local vault directory. Secret payload fields are encrypted, but local
  record metadata exists to support listing and synchronization.

The optional server is zero-knowledge with respect to secret contents, but it
still observes operational information such as account identity, device IDs,
vault IDs, revisions, membership, timestamps, and ciphertext sizes. Zero
knowledge does not mean zero metadata.

## Public API example

```java
Path directory = Path.of("vault-data");
VaultId vaultId = new VaultId(UUID.randomUUID());
Console console = Objects.requireNonNull(System.console(), "A secure console is required");
char[] masterPassword = console.readPassword("Vault password: ");
char[] loginPassword = console.readPassword("Login password: ");

VaultService vaults = new DefaultVaultService(new FileVaultStore(directory));

try (VaultHandle vault =
        vaults.createVault(new CreateVaultRequest(vaultId), masterPassword);
     SecretBuffer username = SecretBuffer.fromChars("alice@example.com".toCharArray());
     SecretBuffer password = SecretBuffer.fromChars(loginPassword)) {

    SecretId id = vault.saveLogin(draft -> draft
            .title("Example account")
            .username(username)
            .password(password)
            .url("https://example.com"));

    vault.withLogin(id, view ->
            view.withPassword(chars -> usePasswordBriefly(chars)));
} finally {
    Arrays.fill(masterPassword, '\0');
    Arrays.fill(loginPassword, '\0');
}
```

The application owns the input password array and must wipe it. Secret views
provide copied data only inside callbacks; callers should avoid converting it
to immutable `String` values.

## Repository structure

```text
keystead-core/src/main/java/top/focess/keystead/
|-- aigc/        AI-generated-content organization context
|-- crypto/      key ownership, algorithms, wrapping, and AEAD
|-- generator/   password, token, SSH, GPG, MFA, and certificate generation
|-- memory/      wipeable and native-locked secret buffers
|-- model/       vault IDs, schemas, encrypted rows, and metadata
|-- recovery/    recovery kits, device requests, and vault-key packages
|-- security/    process-hardening inspection and strict application
|-- service/     public vault, backup, and sync workflows
`-- store/       persistence abstraction and filesystem implementation
```

The module descriptor `module-info.java` declares the named module
`top.focess.keystead.core` and exports the public packages above; the
`memory.internal` and `security.internal` packages hold the FFM backends and
are not exported. Production Java APIs use explicit JSpecify annotations. Tests
cover value invariants, crypto behavior, persistence recovery, synchronization,
backups, device provisioning, schema consistency, nullness semantics, and
native-memory/process-hardening lifecycle and subprocess behavior.

## Build and verification

Requires JDK 25. The Gradle toolchain requests Temurin/Adoptium 25 and
auto-provisions it through the Foojay resolver, so an explicit local install is
optional.

```bash
./gradlew :keystead-core:test --no-daemon --rerun-tasks
./gradlew :keystead-core:classpathTest --no-daemon --rerun-tasks
./gradlew :keystead-core:spotlessCheck
```

Core is a named module (`top.focess.keystead.core`). The `test` task runs on the
module path with `--enable-native-access=top.focess.keystead.core` (plus
`--patch-module`, `--add-reads`, and per-package `--add-opens` so tests can
exercise internals). The separate `classpathTest` source set is a consumer
compatibility fixture that runs on the classpath with
`--enable-native-access=ALL-UNNAMED`. On Windows, use `gradlew.bat`.

CI runs Temurin 25 across four 64-bit tuples: Windows x86-64, Linux x86-64,
Linux AArch64, and macOS AArch64. The library also supports macOS x86-64, but
the GitHub-hosted Intel macOS runner is unavailable, so that leg is omitted.
Spotless runs as an independent, non-skipping check.

## Engineering assessment

### What is strong

- The core, server, and client agree on explicit encrypted-row and lifecycle
  contracts instead of relying on loosely shaped JSON.
- Typed secret schemas are centrally owned and tested across repository
  boundaries.
- Sync conflict, tombstone, device eligibility, and rotation behavior are
  modeled as state transitions with regression coverage.
- Secret-bearing value types are deliberately redacted and short-lived.
- The server can remain operationally useful without receiving decryption
  capability.

### System boundaries

**Browser and mobile integration.** Keystead currently has a JVM desktop
client. There is no browser extension, browser autofill bridge, Android client,
or iOS client. The core can support another client implementation, but those
applications and their platform-specific plaintext boundaries have not been
built.

**Passkeys and biometric unlock.** Keystead does not currently register or
authenticate WebAuthn credentials, store passkeys, or use a platform
authenticator. It also does not unlock vault material through Windows Hello,
Touch ID, or a Linux biometric service. Adding biometric unlock requires an
OS-protected key design that releases wrapping material only after local user
verification; it cannot safely be implemented as a cosmetic alternative to
the master-password field.

**Recovery remains possession based.** Keystead now supports an offline
recovery kit and approval from an existing verified device. Both paths keep
vault-key recovery on clients. The server cannot manufacture recovery if the
user loses the kit, every eligible device, every usable password-wrapped
header, and every backup; permanent loss is the intended consequence of that
zero-knowledge boundary.

**OS protection belongs to the client layer.** Keystead Client can place device
identity material behind Windows DPAPI, macOS Keychain, or Linux Secret
Service, with explicit passphrase-file and memory-only alternatives. Core does
not call operating-system credential APIs and does not treat OS-user protection
as biometric verification.

**Collaboration protects future versions.** Membership, per-device packaging,
and prepared rotation form a complete lifecycle: invitation, acceptance,
package coverage, role enforcement, removal, mandatory rotation, resumption,
and commit. Removing a member cannot erase data already decrypted or copied;
rotation prevents that member from receiving future vault-key generations.

Keystead should currently be evaluated as a serious, test-heavy engineering
foundation and an experimental password-manager system. Production adoption
requires an explicit review of these boundaries and the deployment threat
model.

## Contributing

Contributions should preserve the zero-knowledge boundary, explicit JSpecify
nullness, finite schema vocabulary, backward-readable encrypted formats, and
fail-closed persistence behavior. Add tests at the lowest meaningful boundary,
then run the complete core suite and formatting checks before submitting a
change.

Changes that alter algorithms, authenticated data, vault headers, revisions,
backup formats, or device packages require migration and compatibility tests;
they are protocol changes, not local refactors.
