# Keystead Core

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

Keystead Core is the Java 25 cryptographic and local-vault library used by the Keystead ecosystem. It owns the parts that must remain independent from any desktop UI or server: vault files, key derivation and wrapping, authenticated record encryption, typed secret schemas, encrypted synchronization rows, portable backups, one-off shares, secret-memory handling, and process-hardening helpers.

Core has no accounts, HTTP client, team vaults, members, roles, invitations, persistent server devices, biometric implementation, DPAPI integration, or server database model.

## Ecosystem boundary

| Project | Responsibility |
| --- | --- |
| **Keystead Core** | Local vault format, cryptography, encrypted record import/export, backup, access-request codecs, sharing, and memory protection |
| **[Keystead Client](https://github.com/MidCoard/keystead-client)** | Desktop UI, local vault selection, OS-backed local login (for example Windows Hello or macOS Touch ID), account sessions, sync validation, approval, and restore workflows |
| **[Keystead Server](https://github.com/MidCoard/keystead-server)** | Account sessions, one opaque encrypted record stream per account, short-lived access-request relay, one-off share hosting, and redacted audit events |

One Keystead account represents one personal encrypted record stream. The server does not receive a raw data-encryption key (DEK), vault master password, local-login private key, biometric data, or plaintext secret.

## Vault model

A Keystead vault is one `.kvault` file whose record content is encrypted. It is not JSON and the complete file is not the server sync format.

- Creation generates a random DEK.
- The master password is processed with Argon2id and wraps the DEK; it is not used directly to encrypt records.
- Each record is independently encrypted and authenticated with the DEK and record-specific associated data.
- The plaintext header contains format and routing metadata plus wrapped key slots, never a raw DEK. The outer envelope keeps its algorithm, key id, nonce, and encryption timestamp as plaintext framing metadata; its ciphertext encrypts the complete container body (vault revision, encrypted records, and tombstones). The serialized header is authenticated as the envelope's AAD. The envelope encryption timestamp is informational metadata and is not part of that AAD.
- Records are addressed by a random UUID (`secretId`) generated at creation. The id is a label, not a security boundary: authenticity comes from the DEK, not from identifier uniqueness.
- Closing `VaultHandle` destroys the handle's live key material and releases its file lock.
- `OneFileVaultStore` uses a sibling lock file, recovery journal, and atomic replacement for committed mutations.

`VaultService` is the entry point for creating and opening vaults. `VaultHandle` exposes typed secret operations, encrypted record export/import, local unlock-slot changes, backup creation, and generic public-key wrapping of the active DEK.

## Local login and generic recipient keys

Some public Core names contain `Device`, including `DeviceKeyPair`, `DeviceVaultKeyPackage`, `SlotType.DEVICE`, `addDeviceKey`, and `provisionVault`. In Core these are generic hybrid recipient-key primitives retained as part of the current API and file format. They do not define a persistent server device identity.

[Keystead Client](https://github.com/MidCoard/keystead-client) uses these primitives in two separate ways:

- **Local login:** one optional local private key can be protected by an OS-backed mechanism such as Windows Hello or macOS Touch ID, or by a separate local passphrase. A local `DEVICE` slot wraps the same vault DEK so the local vault can open without typing its master password. This key is never registered with the server.
- **Server restore:** a server session creates a fresh memory-only exchange key pair and request UUID. Another same-account client wraps the open vault's DEK to that ephemeral public key. The new client provisions a local vault, installs a new master-password slot, removes the temporary transfer slot, and destroys the exchange private key.

Core does not store those private keys. The calling application owns their protection, lifetime, user verification, and deletion.

## Server-assisted restore protocol

`VaultAccessRequest` format version 2 contains only:

- request UUID;
- account identifier;
- server origin;
- expiry time;
- exchange-key algorithm;
- ephemeral exchange public key.

`VaultAccessRequestCodec` provides canonical encoding, strict decoding, and a fingerprint that binds the UUID and public key with the rest of the request. `VaultAccessKeyContextCodec` binds DEK wrapping to the canonical request, vault fingerprint, and vault key id.

The server relays the request and the encrypted DEK package. It cannot decrypt the package or approve a request by itself. Approval is possession-based: an already open local vault wraps its DEK to the request's ephemeral public key after the user compares the request fingerprint.

There is no recovery kit in the current product. If no correct local vault or portable backup remains, opaque server records cannot reconstruct the DEK.

## Encrypted synchronization

The personal-vault sync protocol exchanges complete encrypted record snapshots and authenticated deletion markers. It does not upload the entire `.kvault` file. Each server account has one record stream bound to a vault fingerprint. Clients must hold the matching vault identity and DEK, obtained through restore or provisioning; signing into the same account does not make independently created vaults compatible.

### Record identity and verification

Each snapshot contains a `secretId`, `revision`, `secretType`, vault `fingerprint`, encrypted profile, encrypted payload, deletion flag, and `contentKey`. The client adds an `eventId` when uploading it.

- `contentKey` is a DEK-keyed HMAC over the profile plaintext and payload plaintext, or the deletion marker and an empty payload. Profile metadata, including its timestamps and metadata revision, contributes to this identity.
- `eventId` uses the `KVE2` format: SHA-256 over the fingerprint, secret ID, revision, type, deletion flag, and contentKey. Ciphertext is excluded because profile encryption generates a fresh nonce on export. Re-exporting an unchanged snapshot with the current encoding therefore preserves its eventId.
- Core 0.5.4 writes profile properties in sorted order with UTF-8 encoding, fixed LF separators, and no generated timestamp comment. Sets and maps are sorted. User content, including embedded line breaks, is preserved.

The server recomputes eventId and checks the submitted fields, but it cannot authenticate contentKey because it has no DEK. The receiving vault decrypts and authenticates the record with its associated data and verifies the HMAC before storing imported content. A matching eventId alone is not proof that the ciphertext is valid.

Older writers may have used CRLF separators or a different property order. `VaultHandle.canonicalSyncContentKey(record)` first authenticates the original encrypted content and its claimed HMAC, validates the typed payload, then computes an identity using the canonical profile encoding. [Keystead Client 1.1.4](https://github.com/MidCoard/keystead-client) uses this to recognize equivalent historical snapshots without promoting their revision. It does not rewrite the original eventId or bypass verification. Legacy records without a contentKey and unauthenticated empty deletion markers cannot be treated as verified records.

### Upload and download

1. A local edit or deletion receives the next revision from the local vault's monotonic counter. This counter is shared by all records, so an individual record's revisions can have gaps. Exporting or pulling a record does not itself create a new record version.
2. The client sends each snapshot to `POST /api/v1/vault/records`. The server binds the account to the first fingerprint and rejects a different fingerprint with HTTP 409. It deduplicates by `(owner_id, event_id)` and returns the existing event for a repeated upload, even if re-encryption produced different ciphertext. Both new and duplicate submissions return HTTP 201.
3. New events receive a server-assigned `serverSequence` and `createdAt`. The server preserves competing events; it does not decrypt or merge them, reject lower revisions, or choose the correct content for the user.
4. The client downloads events using `GET /api/v1/vault/records?afterSequence=…&limit=…`. Pages contain this account's events in ascending sequence order. The default limit is 100 and the maximum is 500. `highestSequence` is the maximum sequence in that page, or the requested cursor for an empty page. When `hasMore` is true, `nextSequence` must advance the cursor; otherwise it is null.
5. The client verifies and processes the records, then saves its download cursor. `serverSequence` is a position in the event stream, not a content version or evidence that one edit supersedes another. Server timestamps also do not determine which content wins.

`VaultHandle.exportRecordsSince(revision)` exports current snapshots and tombstones above a revision threshold, not every historical local edit. Incremental upload advances its revision watermark after all submissions succeed; selected uploads do not advance that global watermark. Download cursors are isolated by local vault instance, server origin, account, and fingerprint. Restoring a local snapshot starts a new instance so it does not inherit an unrelated cursor.

A download cursor records how far the client has scanned, not that every record was applied: conflicts and rejected records are returned separately, and the cursor can advance past them. A failed multi-page operation may already have imported some records; retrying from the old cursor is supported. Repeated uploads are deduplicated by eventId. Pagination is not a transaction spanning the entire download, so concurrent uploads may appear in later pages or a subsequent sync.

### Comparison and conflict handling

[Keystead Client 1.1.4](https://github.com/MidCoard/keystead-client) compares each secret's current local snapshot with the remote event having the highest revision, using serverSequence to break ties at the same revision. Other events remain visible as history.

| Comparison | Meaning |
| --- | --- |
| Local only / server only | The record exists on only one side; remote content still needs verification before import. |
| Local newer / server newer | One revision number is greater than the other. |
| Matched | The revisions are equal, remote verification succeeds, and the event identity or canonical content identity agrees. |
| Content conflict | The revisions are equal and both contents are valid, but they differ. |
| Hash mismatch | The advertised event identity or content authentication fails. |
| Unverified / legacy unverifiable | The client lacks sufficient verification evidence; this is not a successful match. |

Ordinary Core import preserves incoming revisions. It imports a record when no local version exists or the incoming revision is higher. If the local revision is equal or higher, it reports a conflict when the deletion states differ and otherwise skips the incoming record. A Core import result of `skipped` therefore does not by itself mean the contents match; the client's comparison performs the additional content check.

When the user explicitly selects remote content, the client first authenticates it. Equivalent content at the same revision is skipped. A higher remote revision is imported unchanged. Choosing different content from an equal or older remote revision creates a new local resolution revision, greater than both the local vault watermark and the chosen remote revision. Uploading that resolution allows the other client to import it normally.

Selected local upload sends the chosen snapshots and refreshes comparison. For selected same-revision conflicts or invalid remote events, it promotes the local snapshot once, uploads again, and refreshes. Matched records are not promoted. This is not an unconditional overwrite operation: uploading a lower local revision does not automatically replace a higher remote revision.

The protocol does not perform field-level merging or encode parent-event ancestry. Different offline edits can receive different revision numbers, so a higher number does not prove that it includes the other device's changes. The current protocol cannot identify every concurrent edit from revision numbers alone.

### Deletion and history

Normal synchronized deletion keeps the secretId and writes a higher-revision tombstone. Its `encryptedProfile` contains an authenticated deletion-control envelope, `envelope` is empty, and its contentKey commits to the deletion marker. The receiving vault verifies the marker before applying it. Older active snapshots cannot silently undo a newer local tombstone; an explicit resolution can restore chosen content as a new version.

`DELETE /api/v1/vault/records/{secretId}` is a separate history-purge operation. It removes that secret's server events without creating a tombstone or deleting copies on other clients. Those clients can upload the record again. Clearing the entire stream also releases its fingerprint binding. Purging history is not the normal way to propagate deletion or resolve a sync mismatch.

The current protocol has no stream-generation negotiation for server rollback or replacement. A saved cursor beyond a restored server's history can return an empty page; a full refresh or cursor reset is needed to reconcile that state. An empty incremental response alone does not prove that both vaults match.

## Data storage format

This section is the concrete reference for how Keystead stores data on disk and on the wire. Conceptual background is in [Vault model](#vault-model) and [Encrypted synchronization](#encrypted-synchronization); see `VaultFileFormat`, `VaultContainerBody`, and `SyncRecordCodec` for the exact byte layout. All integers are big-endian and variable-length fields carry a length prefix.

### Local vault file (`.kvault`)

A vault file is one opaque container with two parts.

**Plaintext header** — the format magic (`KSTEAD`) and version, the vault **fingerprint** (a stored, non-secret 64-bit routing identity), the vault key id, and one or more **key slots**. A new vault derives its initial fingerprint from the initial passphrase and KDF salt; restored or provisioned copies preserve that fingerprint even when they install a different local passphrase. Each slot wraps the same data-encryption key (DEK) for a different recipient: a `PASSPHRASE` slot wraps it under an Argon2id passphrase-derived key (and carries its own KDF parameters), and zero or more `DEVICE` slots wrap it to a device public key. Any single slot unlocks the vault. The header closes with created/updated timestamps.

**AEAD envelope** — one AES-256-GCM block whose ciphertext is the encrypted **container body**. The serialized header bytes are the envelope's additional authenticated data (AAD), so the container AEAD authenticates the header and ciphertext. A wrong passphrase or tampered passphrase slot normally fails earlier while authenticating the wrapped DEK; after a DEK is recovered, a modified header, nonce, or ciphertext fails container authentication. The algorithm, key id, nonce, and encryption timestamp are plaintext framing metadata; the timestamp is informational and not authenticated.

### Container body (what the DEK decrypts)

The decrypted container body is a flat byte array holding:

- the vault revision (a monotonic counter),
- the active **secret records**,
- the **tombstones** (deletion markers).

Each active record stores:

| field | meaning |
| --- | --- |
| `secretId` | the record's stable UUID |
| `secretType` | `LOGIN_PASSWORD`, `SECURE_NOTE`, `SSH_KEY`, `API_TOKEN`, `GPG_KEY`, `MFA_SECRET`, `CERTIFICATE`, or `GENERIC_SECRET` |
| profile | non-secret metadata: title, classification (category/provider/software/account/labels), tags, attributes, created/updated timestamps, and the record revision |
| payload envelope | a second AES-256-GCM block (also under the DEK) whose ciphertext is the encrypted **payload** — the actual secret values. Its AAD binds the payload to the vault fingerprint and the record's metadata, so a payload cannot be swapped onto a different record. |

Each tombstone stores `secretId`, `secretType`, the revision at which the secret was deleted, and the deletion timestamp. A tombstone whose revision is newer than an active record hides that record.

**Why two encryption layers?** The outer envelope protects the whole file at rest after the DEK is recovered from any valid key slot. The inner per-record payload envelope makes each record a self-contained encrypted unit, so records can be synced to the server or written to a backup archive as opaque ciphertext. The server never receives the DEK; a portable backup contains an independently password-wrapped copy, never the raw DEK. Both layers use the same DEK; the inner layer exists for per-record portability, not for extra strength.

**Payload formats** (the plaintext inside a record's payload envelope):

| secretType | payload fields |
| --- | --- |
| `LOGIN_PASSWORD` | url, username, password, notes |
| `SECURE_NOTE` | body |
| `SSH_KEY` | publicKey, privateKey, passphrase (optional) |
| `API_TOKEN` | token, notes |
| `GPG_KEY` | publicKey, privateKey, passphrase (optional) |
| `MFA_SECRET` | seed, otpauthUri (optional), recoveryCodes (optional); legacy `secret` is accepted as a seed alias |
| `CERTIFICATE` | certificate, privateKey, passphrase (optional) |
| `GENERIC_SECRET` | arbitrary custom fields |

`LOGIN_PASSWORD` and `SECURE_NOTE` use dedicated payload encodings; the other types share a generic name→value map whose expected field names come from the type's schema.

### Sync record and server storage

Synchronization moves one record at a time as an `EncryptedSyncRecord`. The client POSTs a JSON object to `POST /api/v1/vault/records` with:

| field | meaning |
| --- | --- |
| `eventId` | the record's stable identity hash (see below) |
| `fingerprint` | the vault fingerprint, as lowercase hex |
| `secretId` | record UUID |
| `revision` | monotonic record revision |
| `secretType` | the secret type name |
| `encryptedProfile` | the profile (title/classification/tags/attributes/timestamps/revision) encrypted under the DEK |
| `envelope` | the record's payload envelope (the same per-record ciphertext stored locally) |
| `deleted` | tombstone flag |
| `contentKey` | a DEK-keyed HMAC committing to the profile/deletion marker and payload plaintext (see below) |

The server stores these in two tables:

- **`personal_vaults`** — one row per account: `owner_id`, `fingerprint`, `created_at`, `updated_at`. The first upload binds the account to that fingerprint; a later upload with a different fingerprint is rejected with HTTP 409.
- **`vault_record_events`** — an append-only event log: `server_sequence` (server-assigned, monotonic), `owner_id`, `event_id`, `fingerprint`, `secret_id`, `local_revision`, `secret_type`, `encrypted_profile`, `envelope`, `content_key`, `deleted`, `created_at`. Uploads do not supply the server event timestamp; the server assigns `server_sequence` and `created_at`. Encrypted profile and envelope data retain their own timestamps.

The server never decrypts anything and never receives the DEK. It checks that the submitted `eventId` is structurally consistent with the submitted identity fields and `contentKey`, then deduplicates by `(owner_id, event_id)`. This check is not proof of DEK possession because the server cannot authenticate the caller-supplied `contentKey`; an open receiving vault performs the authoritative check by decrypting the record and recomputing the DEK-keyed HMAC. Clients read the stream with `GET /api/v1/vault/records?afterSequence=…` and purge a secret's history with `DELETE /api/v1/vault/records/{secretId}`.

### Record identity, deduplication, and collisions

Three derived values give each record a stable, ciphertext-independent identity:

- **fingerprint** = initially `HMAC-SHA-256(wrappingKey, "keystead-vault-fingerprint-v3" ‖ kdfSalt)`, truncated to the first 64 bits (8 bytes / 16 hex chars), then persisted and preserved by restore/provisioning. It is a non-secret routing token binding an account to one vault.
- **contentKey** = base64url `HMAC-SHA-256(DEK, "keystead-sync-content-v1" ‖ len(profile) ‖ profile ‖ len(payload) ‖ payload)`. Commits to the record plaintext; keyed by the DEK so the server gains no offline guessing oracle.
- **eventId** = base64url `SHA-256("KVE2" ‖ fingerprint ‖ secretId ‖ revision ‖ secretType ‖ deleted ‖ contentKey)`. The deduplication key. Ciphertext is deliberately excluded, so re-exporting an unchanged record (which re-encrypts the profile with a fresh nonce) yields the same `eventId`.

**Duplicates and collisions:**

- **Same `eventId`**, for rows that pass receiving-vault verification, means the same logical record content. The server itself treats it as a structural deduplication key, not as proof of authenticity. It deduplicates by `(owner_id, event_id)`: re-uploading an unchanged record returns the existing row unchanged (idempotent). `eventId` is a 256-bit hash, so accidental collision between valid records is computationally infeasible.
- **Same `secretId`, different revision** means the same secret updated over time. The server retains uploaded events unless explicitly purged; the client selects the highest revision for that `secret_id`, breaking same-revision ties by `server_sequence`. `secretId` is a UUID (122 bits of randomness), so accidental reuse is infeasible; reuse across revisions is the intended history mechanism.
- **`contentKey`** is a 256-bit HMAC; collisions are computationally infeasible.

**Fingerprint collisions (the 64-bit case).** The fingerprint is truncated to 64 bits, so a birthday collision becomes theoretically possible around 2³² vaults. Keystead treats this as acceptable and does not add an extra collision check, for two reasons. First, the space is far larger than any realistic deployment. Second, and more important, the DEK-bound `contentKey` is the real per-record authority: even if two different vaults shared a fingerprint, a record encrypted under vault A's DEK could not be imported by vault B's client because decryption or `contentKey` verification would fail. A fingerprint collision can therefore cause routing and availability noise but does not by itself expose record plaintext. Across different accounts there is no conflict at all (`owner_id` separates the streams); on the same account the server would simply treat the two vaults as one. Widening the fingerprint to 128 bits would raise the birthday bound further but would change the on-disk and sync formats and break existing vaults, so it is not done.

## Portable backup

`FullVaultBackupService` creates and restores complete password-protected backups. A portable backup contains enough encrypted material to create a new local vault without the original vault file, original master password, server, or local-login key.

Restore requires:

- the `.ksbackup` file;
- its independent backup password;
- a new target `.kvault` path that does not already exist;
- a new local master password.

Restore does not silently overwrite an existing target.

## Typed secrets and generators

Core provides dedicated payload formats for login passwords and secure notes plus schemas for structured secret types. Vault secret-field values generally enter through mutable `SecretBuffer` values and are exposed through short-lived view callbacks where the API permits.

Generators cover passwords, API tokens, SSH keys, OpenPGP keys, MFA seeds and TOTP values, and X.509 certificate bundles. Generated private material uses closeable or mutable containers so callers can promptly overwrite Core-owned buffers. This is best-effort in a managed JVM: immutable strings and copies made by callers cannot be reliably wiped by Core.

## One-off sharing

`ShareService` creates a self-contained `keystead-share:v1` encrypted string protected by an independent temporary passphrase. The recipient needs neither an account nor a vault. [Keystead Server](https://github.com/MidCoard/keystead-server) may host this opaque string with expiry and optional burn-after-reading behavior, but Core performs the encryption and decryption.

## Cryptography

The current implementation uses:

| Purpose | Implementation |
| --- | --- |
| Master-password KDF | Argon2id |
| Record and metadata encryption | AES-256-GCM with domain-separated associated data |
| Recipient/exchange wrapping | Google Tink ECIES P-256, HKDF-HMAC-SHA256, AES-128-GCM |
| Sync content identity | DEK-keyed HMAC-SHA-256 content keys with `KVE2` SHA-256 event ids |
| Vault routing fingerprint | Truncated, domain-separated HMAC-SHA-256 derived at initial vault creation and then persisted |
| SSH/OpenPGP/X.509 generation | Bouncy Castle |

Google Tink depends on protobuf for its own key serialization. Keystead does not use protobuf as its client/server wire protocol. The `protobuf-java` `sun.misc.Unsafe` warning on JDK 25 is a transitive dependency compatibility warning; removing protobuf without replacing Tink would remove the active hybrid-encryption implementation.

## Secret memory and process hardening

Core provides locked native-memory backends and process inspection/hardening helpers. These controls reduce accidental persistence and post-crash disclosure; they cannot protect plaintext from code, malware, a debugger, or a privileged process that already controls the live application.

Applications must:

- grant native access to `top.focess.keystead.core` or the unnamed module;
- decide whether native-memory failure should be fatal or whether an explicit heap fallback is acceptable;
- keep plaintext callbacks short and wipe caller-owned arrays;
- apply strict process hardening only at an appropriate application lifecycle boundary;
- understand that OS-backed authentication such as Windows Hello and macOS Touch ID is implemented in [Keystead Client](https://github.com/MidCoard/keystead-client), not Core, and is only a local convenience gate.

## Build and test

Requirements:

- JDK 25 (Adoptium toolchain in the Gradle build);
- Gradle wrapper included in the repository.

Run all named-module and classpath-consumer tests:

```powershell
.\gradlew.bat check --no-daemon
```

Dependency coordinates (Maven Central):

```kotlin
implementation("top.focess:keystead-core:0.5.4")
```

Client and Server consume only released Maven Central coordinates. Local-consumption mechanisms (`mavenLocal`, composite builds) are never committed; release first, then consume.

The module name is `top.focess.keystead.core`. Its exported packages are `access`, `aigc`, `crypto`, `generator`, `memory`, `model`, `security`, `service`, `share`, and `store` under `top.focess.keystead`.

## Security limits

- A compromised live process can observe plaintext while the vault is open.
- A user who can satisfy the configured OS-backed or local-login-passphrase check can use that local unlock slot.
- Revoking a local slot does not erase plaintext or keys already copied by an attacker.
- An append-only server can retain ciphertext and traffic metadata, including account identity, vault fingerprint, record identifiers, revisions, timestamps, and sizes.
- A forged server event (for example one replaying a known `secretId`) cannot enter a local vault: import authenticates every row against the DEK and its content key before storing. The worst case is availability noise, which re-uploading repairs.
- Losing every usable local vault and portable backup permanently loses access to opaque server records.
- The API and on-disk formats are still under active development; pin exact versions.
