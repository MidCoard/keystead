# Keystead Core Security Hardening Design

## Scope

This change hardens only `keystead-core`. It does not inspect or modify the
server or desktop client. Existing encrypted vaults, PBKDF2 headers, recovery
packages, and public constructors remain readable. Existing public constructor
and accessor signatures are retained for source compatibility; binary
compatibility is not promised before version 1.0.

The work addresses the reproducible findings from the defensive core review:
rotation/mutation races, non-atomic secret destruction, resource-exhaustion
inputs, ambiguous recovery contexts, avoidable secret copies, unsupported
envelope versions, incorrect AES-256 key sizes, and static child-path symlink
redirection. It also adds narrow provider seams so later KDF and secret-memory
implementations do not require rewriting the secret domain model.

## Threat Model

Keystead protects encrypted vault material from an attacker who obtains local
vault files, backups, or synchronized ciphertext without an unlocking secret.
It minimizes the lifetime and number of plaintext/key copies while the vault is
unlocked.

Keystead cannot hide an actively used secret from an attacker who can debug the
process, inject code or a Java agent, read the process address space, control
the operating-system kernel, or replace the running application. Heap arrays,
native pages, CPU registers, JCA/Tink/Bouncy Castle objects, and UI buffers are
all observable inside that stronger compromise boundary. Memory locking can
prevent paging and ordinary heap-dump inclusion; it is defense in depth, not a
solution to live process-memory disclosure.

## Lifecycle Serialization

Each `DefaultVaultHandle` owns one lifecycle monitor. Every operation that
reads the live vault key, exposes decrypted data, mutates records, prepares a
rotation, commits a prepared rotation, or closes the handle participates in
that monitor.

A mutation that began first completes before rotation takes its snapshot. Once
rotation preparation becomes active, later mutations fail before their caller
callback runs. Closing waits for in-flight secret/key use, wipes the vault key,
and prevents new work. Prepared-rotation state has its own atomic close/commit
transition while coordinating parent-handle completion through the lifecycle
monitor.

This intentionally serializes operations on one unlocked handle. Independent
handles and independent vaults remain concurrent.

## Secret Memory Ownership

`SecretBuffer`, `VaultKey`, and `DeviceKeyPair` make copy/use/close atomic. A
successful callback either completes before `close()` returns, or access is
rejected before a readable copy is produced. All owned heap arrays are wiped on
close, replacement, exceptional construction, and temporary conversion paths.

Avoidable copies are removed:

- MFA Base32 output is written directly to a mutable `char[]`.
- Private-key serialization uses a wipeable output stream.
- Device private keys gain callback-scoped access; the existing copying
  accessor is retained and deprecated for compatibility.
- Recovery kits gain `SecretBuffer`/mutable-character encoding APIs. The
  existing `String` API is retained and deprecated because callers may still
  need compatibility, but it is documented as heap-dump visible.
- Charset conversion uses caller-owned work buffers that are wiped on success
  and failure.

`SecretBuffer` remains the public facade. A small `SecretMemoryProvider` and
`SecretMemory` contract is introduced behind it. The default provider uses
wiped heap arrays. Callers may explicitly supply another provider, and
`DefaultCryptoService` can use the same provider for vault/device private key
ownership. A later optional module may implement locked native pages without
changing vault records, drafts, views, or generator APIs. No global mutable
provider is installed.

## Cryptographic Algorithm Abstraction

`EncryptedEnvelope` is already algorithm-labelled and `AeadCipher` already
separates payload algorithms. The hardening work enforces envelope version 1
and exactly 32-byte keys for implementations labelled AES-256-GCM.

Password KDF handling gains two explicit abstractions:

- `KdfParameters`: algorithm identifier, salt, and a canonical bounded map of
  integer parameters.
- `PasswordKeyDerivation`: validates parameters and derives a fixed-size key.

Default providers cover the existing PBKDF2-HMAC-SHA-256 and
PBKDF2-HMAC-SHA-512 formats. `DefaultCryptoService` selects an explicitly
registered provider; unknown algorithms or parameters are rejected. It never
falls back to another KDF.

`VaultHeader` retains the legacy constructor and accessors while carrying the
canonical parameter object. File and backup codecs continue writing the legacy
PBKDF2 fields and also support canonical parameter entries. Old vaults map to
`iterations`; future Argon2id support can add `memoryKiB`, `parallelism`, and
`iterations` through a new provider without changing the secret model. Adding
such an algorithm still requires explicit header-format migration tests and
client rollout; it is intentionally not automatic.

Argon2id itself and a native locked-memory provider are not implemented in this
change.

## Input and File Boundaries

The following limits are enforced before expensive allocation or cryptographic
work:

- stored properties file: 1 MiB;
- encrypted envelope ciphertext: 1 MiB;
- envelope AAD: 64 KiB;
- encoded sync profile or envelope: 2 MiB each;
- wrapped device/recovery vault-key package: 1 MiB;
- password-KDF salt: 64 bytes maximum;
- PBKDF2 iterations: 10,000,000 maximum;
- KDF parameter entries: 16 maximum, ASCII names up to 64 characters, positive
  integer values no greater than `Integer.MAX_VALUE`.

The limits align with the existing 1 MiB backup-entry boundary and leave room
for format overhead. Boundary tests cover the maximum and the first rejected
value. File loading reads through a bounded buffer rather than trusting a
racy pre-read file-size check.

`FileVaultStore` resolves its root to an absolute normalized path and rejects
existing symbolic-link descendants for managed files/directories before use.
Containment is checked for every managed path. This blocks static redirection;
it does not claim to eliminate every filesystem race against an attacker who
can continuously rewrite a privileged process's vault directory.

## Recovery Context Compatibility

New recovery wrapping contexts use a version-2 canonical binary encoding:
magic bytes followed by length-prefixed UTF-8 fields and a fixed-width
generation. Delimiter characters therefore have no structural meaning.

New packages are wrapped with version 2. Opening first tries version 2 and then
the legacy version-1 text context so existing recovery packages remain usable.
The legacy fallback is compatibility-only and is never used for new wrapping.

## Testing and Verification

Every behavioral fix follows red-green TDD. Tests include:

- deterministic latch-based mutation/rotation and close/access races;
- exact size/KDF/version/key-length boundaries;
- colliding legacy recovery tuples that produce distinct version-2 contexts;
- recovery legacy-open compatibility;
- secret-owner exceptional cleanup and callback behavior;
- safe recovery-kit encoding and direct MFA encoding;
- symlink rejection where the platform permits link creation;
- existing vault/header/backup compatibility;
- complete `:keystead-core:test` and `spotlessCheck` verification.

The implementation is reviewed after each coherent task and once again as a
whole branch. Only the Git-backed Core repository is committed. Local notes and
the pre-existing modified test in the main checkout remain untouched.

## Residual Risks

- An unlocked vault key is necessarily readable by sufficiently privileged
  live-memory inspection while cryptographic operations use it.
- JCA, Tink, Bouncy Castle, the JVM, garbage collector, JIT compiler, and UI
  code may create provider-owned copies Keystead cannot wipe.
- Deprecated compatibility APIs returning secret `String` or private-key
  arrays remain unsafe if callers retain their results.
- Static symlink checks reduce accidental/standing redirection but are not a
  substitute for running Keystead without elevated privileges and protecting
  the vault directory with operating-system permissions.
- PBKDF2 compatibility remains; a separately versioned Argon2id migration is
  still required before treating the password KDF as the preferred modern
  format.
