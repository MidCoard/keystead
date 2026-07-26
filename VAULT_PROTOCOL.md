# Keystead Vault Protocol (v2)

This document is the **authoritative public specification** of the Keystead v2
vault protocol: the on-disk vault file format, the key model, the cryptographic
constructions, device provisioning, recovery, synchronization, and
single-secret sharing. It is the contract shared by Keystead Core (this
repository, the reference implementation), Keystead Server, and Keystead
Client.

v2 is a **clean break** from v0.2. There is no migration reader: a v0.2
folder-vault is rejected gracefully, never read. The protocol version is
`2`; the AAD label is `v3`; the sync profile is `v2`; the fingerprint label is
`v2`.

> Status: design specification. The Core implementation lands this format on the
> `feat/v2-one-file-vault` branch. Server and client are separate-repo
> follow-ups that implement against this contract.

---

## 1. Goals

1. **One-file vault.** A vault is a single opaque `.kvault` file (KeePass-style),
   not a folder of properties files.
2. **No vault id.** A vault is identified locally by its **file path** and
   unlocked by a **passphrase** (or a device/recovery key). There is no UUID.
3. **Passphrase-bound fingerprint** is the server routing identity and the AAD
   binding for records.
4. **Multi-slot header.** The same vault key (DEK) is wrapped under several
   independent unlock credentials: a passphrase, one or more device keys, and one
   or more recovery keys. Any single slot unlocks the vault.
5. **Server = user accounts.** Signup/login; routing is user-scoped, then
   fingerprint-scoped within the account.
6. **Re-keyed per-record sync.** Encrypted deltas, keyed by fingerprint.
7. **Single-secret sharing.** Share one secret as a self-contained encrypted
   string (and optionally a server-hosted short link), unlockable with a
   temporary passphrase. Folded into v2.

---

## 2. Threat model and the zero-knowledge boundary

Keystead is **zero-knowledge**: the server never sees a plaintext secret, a raw
token, a passphrase, a KDF salt, a wrapping key, the DEK, or a wrapped vault
key. The server stores only:

- account and verified-device state;
- the **fingerprint** (an opaque, non-secret routing token);
- **encrypted sync rows** (per-record ciphertext, already encrypted on the
  client);
- **device/recovery key packages** (the DEK wrapped to a recipient's public
  key - ciphertext the server cannot unwrap);
- **share blobs** (self-contained encrypted single-secret shares - ciphertext
  the server cannot decrypt);
- row counts and sizes (an inherent, accepted metadata leak, unchanged from
  v0.2).

The vault file is **never uploaded**. It lives on the user's device(s); records
reach other devices via encrypted sync rows (server-mediated) or via an
out-of-band file copy / backup restore.

**Offline attack model.** The vault file is the high-value offline-attackable
target. Its protection is the **Argon2id** memory-hard KDF gating the
passphrase-wrapped DEK, plus the whole-vault AEAD tag. An attacker who obtains
the file must guess the passphrase, paying the full Argon2id cost per guess,
and verifies each guess against the AEAD tag.

---

## 3. Cryptographic primitives

| Purpose | Primitive | Notes |
| --- | --- | --- |
| Vault DEK (data-encryption key) | AES-256-GCM (Tink) | Encrypts the vault container body and per-record fields. |
| Passphrase KDF (PASSPHRASE slot) | **Argon2id** (Bouncy Castle 1.84) | Memory-hard; parameters `{iterations, memory, parallelism}` travel in the slot. |
| Share temp-passphrase KDF | PBKDF2-HMAC-SHA-256 (Tink) | For single-secret shares; bounded by a min-strength floor. |
| DEK wrapping (PASSPHRASE slot) | AEAD under `Argon2id(passphrase, salt)` | The wrapping key (KEK) is the Argon2id output. |
| DEK wrapping (DEVICE / RECOVERY slots) | Tink hybrid encryption (HPKE-style) | `HybridEncrypt(recipientPublicKey, DEK, context)`; unwrapped with the recipient private key. |
| Device proof key | Ed25519 | Signs server login challenges (device auth); distinct from the wrapping keypair. |
| Fingerprint | `HMAC-SHA-256(wrappingKey, label ‖ kdfSalt)` truncated to 128 bits | Non-secret routing identity; stable across DEK rotation. |
| Whole-vault integrity | AEAD tag over the container with the serialized header as AAD | Header tampering and a wrong passphrase both fail the tag cleanly. |
| Per-record integrity (sync) | AEAD per field envelope, AAD = `fingerprint ‖ secretId ‖ revision` | Each sync row is self-authenticating. |

The KDF layer is pluggable (`PasswordKeyDerivation` registered by algorithm name
in `DefaultCryptoService`). `KdfParameters` is a generic
`(algorithm, salt, Map<String,Integer> parameters)` so any approved KDF's
parameters round-trip in a slot.

---

## 4. Vault file format

File extension: `.kvault` (e.g. `personal.kvault`). All integers are big-endian;
all lengths are unsigned.

```
HEADER (plaintext; also the container AAD)
  magic[6]              "KSTEAD"
  version[1]            2
  fingerprint[16]       HMAC-SHA-256(wrappingKey, label‖salt), low 128 bits
  vaultKeyId            u16 len + UTF-8      (the DEK key id; binds container to key)
  slotCount             u16                  (>= 1)
  slots[slotCount]:
    slotType[1]         1=PASSPHRASE, 2=DEVICE, 3=RECOVERY
    slotKeyId           u16 len + UTF-8      ("passphrase" | deviceId | enrollmentId)
    kdfAlgorithm        u16 len + UTF-8      (PASSPHRASE only; else empty)
    kdfSalt             u16 len + bytes      (PASSPHRASE only; else empty)
    kdfParamCount       u16                  (PASSPHRASE only; else 0)
    kdfParams[paramCount]:
      name              u16 len + UTF-8      ("iterations" | "memory" | "parallelism" | ...)
      value             s32
    wrappedVaultKey     s32 len + bytes      (slot-specific wrapping of the DEK)
  createdAt             s64 epochSeconds + s32 nanos
  updatedAt             s64 epochSeconds + s32 nanos
ENVELOPE (ciphertext; AAD = the serialized header bytes above)
  envelopeVersion[1]    1
  algorithm             u16 len + UTF-8
  keyId                 u16 len + UTF-8      (== vaultKeyId)
  nonce                 u8 len + bytes
  ciphertext            s32 len + bytes      (encrypted container body)
  encryptedAt           s64 epochSeconds + s32 nanos
```

### 4.1 Why the header is plaintext

The header must be readable before any key is derived: the unlock code reads the
slots to decide which credential to use, and reads the KDF parameters to derive
the passphrase wrapping key. Header secrecy is **not** required - the DEK and
the container ciphertext are what protect secrecy, and the header is
authenticated (it is the container AAD, so any tampering breaks the AEAD tag).

### 4.2 Why the fingerprint is stored in the header

The fingerprint is a **non-secret routing identity**, not a secret. It is stored
in the plaintext header so that a passphrase-less open (DEVICE or RECOVERY slot)
can recover the routing identity without deriving it (it has no wrapping key to
derive it from). Storing it is safe because:

- it is a PRF output (truncated HMAC) and leaks no structural information about
  the wrapping key or passphrase;
- knowing the fingerprint grants nothing on the server - every server action on
  a fingerprint requires account authentication (a verified device key or API
  token);
- it adds no offline-brute-force oracle beyond the wrapped DEK already present:
  each passphrase guess still pays the full Argon2id cost, whether verified
  against the AEAD tag or the fingerprint.

The fingerprint is integrity-protected by the container AEAD tag (the header is
the AAD), so a tampered stored fingerprint is detected on open.

### 4.3 Whole-vault AEAD

The container ciphertext is `AEAD(DEK, nonce, containerBody, AAD=headerBytes)`.
The AEAD tag is therefore a **whole-vault MAC**: tampering with the header, the
slots, the fingerprint, or the ciphertext is detected on open, and a wrong
passphrase (which yields a wrong DEK) fails the tag cleanly. There is no
separate integrity pass.

### 4.4 Atomic write

A save serializes the whole container, writes to `<file>.tmp`, `fsync`s, atomically
moves it into place (`Files.move(ATOMIC_MOVE)`), and `fsync`s the directory. A
single writer is enforced with a `FileLock` (carried over from `FileVaultStore`).
Whole-vault atomicity makes multi-record transactions trivial: a mutation just
rewrites the container under the lock.

---

## 5. Key slots

Every slot wraps the **same DEK**. A vault opens by satisfying **any one** slot.

### 5.1 PASSPHRASE slot

- `wrappingKey = Argon2id(passphrase, kdfSalt, {iterations, memory, parallelism})`.
- `wrappedVaultKey = AEAD(wrappingKey, DEK, AAD="keystead-vault-key-wrap-v2|passphrase")`.
- On open: derive `wrappingKey` from the passphrase and the slot's salt/params,
  unwrap the DEK, then derive the fingerprint
  `HMAC-SHA-256(wrappingKey, "keystead-vault-fingerprint-v2" ‖ kdfSalt)` (low 128
  bits) and verify it equals the stored header fingerprint (defense in depth; the
  tag already protects it).

### 5.2 DEVICE slot

- `wrappedVaultKey = HybridEncrypt(devicePublicKey, DEK, context="keystead-vault-key-wrap-v2|device:<deviceId>")`.
- On open: `HybridDecrypt(devicePrivateKey, wrappedVaultKey, context) -> DEK`.
  The fingerprint is read from the header (the device has no passphrase to
  derive it).
- `slotKeyId` is the device id. A vault may carry one DEVICE slot per trusted
  device.

### 5.3 RECOVERY slot

- `wrappedVaultKey = HybridEncrypt(recoveryPublicKey, DEK, context="keystead-vault-key-wrap-v2|recovery:<enrollmentId>")`.
- On open: `HybridDecrypt(recoveryPrivateKey, wrappedVaultKey, context) -> DEK`.
  The fingerprint is read from the header.
- `slotKeyId` is the recovery enrollment id.

### 5.4 Slot lifecycle

- **createVault**: one PASSPHRASE slot (Argon2id). Optionally zero DEVICE/RECOVERY
  slots initially.
- **add device** (provision): wrap the DEK to the new device's public key, append
  a DEVICE slot, re-AEAD the container (header changed). The new device also
  receives a **server-stored device package** (`DeviceVaultKeyPackage`, carrying
  the wrapped DEK + fingerprint) for first-time bootstrap, after which it opens
  via its local DEVICE slot with no server round-trip.
- **add recovery**: wrap the DEK to a recovery public key, append a RECOVERY slot.
- **rotateVaultKey** (DEK rotation, passphrase unchanged): generate a new DEK,
  re-encrypt the container under it, re-wrap into **every** existing slot (the
  passphrase wrapping key is unchanged, so the fingerprint is unchanged), re-AEAD.
- **changePassphrase**: new salt + new Argon2id wrapping key -> re-wrap the DEK
  into the PASSPHRASE slot under the new wrapping key, recompute the fingerprint
  (it changes), update the stored fingerprint, re-AEAD, and re-bind to the server
  account under the new fingerprint (UX: the user is warned this re-binds sync).
- **remove slot** (revoke device / recovery): drop the slot, re-AEAD. Revoking a
  device protects **future** access; it cannot erase records the device already
  decrypted.

---

## 6. Container body

The container body (the AEAD plaintext) is a length-prefixed binary serialization
of the record set. Everything inside is ciphertext at rest (protected by the
container AEAD), fixing the v0.2 metadata-plaintext gap (titles are no longer
plaintext on disk).

```
BODY (plaintext; becomes the envelope ciphertext after AEAD)
  bodyVersion[1]        1
  vaultRevision         s64
  recordCount           s32
  records[recordCount]:    (EncryptedSecretRecord, re-keyed: AAD uses fingerprint)
    secretId            u16 len + UTF-8
    classification      u8
    createdAt           s64 + s32
    updatedAt           s64 + s32
    revision            s64
    fieldCount          s32
    fields[fieldCount]:    (per-field EncryptedEnvelope; self-authenticating for sync)
      envelopeVersion[1]
      algorithm         u16 len + UTF-8
      keyId             u16 len + UTF-8
      nonce             u8 len + bytes
      ciphertext        s32 len + bytes
      encryptedAt       s64 + s32
  tombstoneCount        s32
  tombstones[tombstoneCount]:    (DeletedSecretRecord)
    secretId            u16 len + UTF-8
    deletedAt           s64 + s32
    revision            s64
```

Per-field envelopes carry their own AAD (`SecretRecordAad.encode(fingerprint,
secretId, classification, tags, attributes, timestamps, revision)`), so an
individual record pulled from sync is self-authenticating and cannot be
substituted across vaults (the fingerprint binds it). The container AEAD is the
outer protection; the per-field AEAD is the per-record protection that travels
in sync.

---

## 7. Envelope encryption summary

```
passphrase  --Argon2id-->  wrappingKey (KEK)
                              |
                 PASSPHRASE slot:  AEAD(KEK, DEK)            \
device priv  <--HybridDecrypt--  DEVICE slot:  HybridEnc(pub, DEK)   -->  DEK  -->  AEAD(DEK, containerBody, AAD=header)
recovery priv<--HybridDecrypt--  RECOVERY slot: HybridEnc(pub, DEK)  /
wrappingKey  --HMAC-->  fingerprint (routing identity, stored in header)
```

The DEK is a random per-vault key. Rotating the DEK does not rotate the
passphrase wrapping key, so the fingerprint is stable across DEK rotation.

---

## 8. Open / create / rotate flows

- **createVault(path, passphrase)**: generate DEK + salt + Argon2id params ->
  derive wrappingKey -> compute fingerprint -> build header with one PASSPHRASE
  slot (wrapped DEK) + stored fingerprint -> empty container body -> write file.
- **openVault(path, passphrase)**: read header -> pick the PASSPHRASE slot ->
  derive wrappingKey -> unwrap DEK -> (verify derived fingerprint == stored) ->
  verify container AEAD tag -> decrypt body -> in-memory record set.
- **openVaultWithDeviceKey(path, devicePrivateKey)**: read header -> find a
  DEVICE slot whose `slotKeyId` matches this device -> HybridDecrypt -> DEK ->
  read fingerprint from header -> verify tag -> decrypt. No server round-trip;
  no passphrase.
- **provisionVault(path, devicePackage, devicePrivateKey)**: first-time bootstrap
  on a new device. Unwrap the DEK from the server-stored `DeviceVaultKeyPackage`
  (which also carries the fingerprint), create a local file with a DEVICE slot
  (the DEK wrapped to this device) + the stored fingerprint + an empty container,
  then sync-pull records from the server. After provisioning, the device opens
  via `openVaultWithDeviceKey` with no package. (No file copy required.)
- **openVault via recovery**: restore a `.kvault` file (backup/copy) -> find the
  RECOVERY slot -> HybridDecrypt with the recovery private key -> DEK -> decrypt.
  If no file survives, recovery cannot restore old records (they are gone); the
  user creates a new vault and re-binds.
- **rotateVaultKey()**: new DEK -> re-encrypt container -> re-wrap into every
  slot -> re-AEAD. Fingerprint unchanged. Device packages on the server are
  re-published (re-wrapped to each device).
- **changePassphrase()**: new salt + wrapping key -> re-wrap PASSPHRASE slot ->
  recompute fingerprint -> update header -> re-AEAD -> re-bind server.

---

## 9. Device provisioning and rotation

The device-key system is **kept** from v0.2 and re-keyed to the fingerprint. A
device key is a Tink **hybrid asymmetric** keypair used to wrap/unwrap the DEK
for a recipient device without the passphrase. A separate **Ed25519 proof
keypair** signs server login challenges (device auth), distinct from wrapping.

- `DeviceVaultKeyPackage = { fingerprint, vaultKeyId, keyAlgorithm,
  encryptedVaultKey }` - the transportable wrapped-DEK blob, server-stored for
  first-time bootstrap. The `fingerprint` field is new in v2 (non-secret; lets a
  passphrase-less open route sync).
- `prepareVaultKeyRotation()` / `PreparedVaultKeyRotation`: stages a new DEK,
  wraps it to each target (DEVICE / AUTOMATION / RECOVERY) via
  `wrapVaultKeyPackageForDevice`, uploads the packages, then
  `commitWithDevicePackage` swaps the DEK and re-wraps every slot. Resumable.
- Vault-share targets (`ServerVaultRotationTargetType`): **DEVICE** (another of
  the user's devices), **AUTOMATION** (API token / CI principal), **RECOVERY**
  (recovery enrollment).

---

## 10. Recovery

Recovery delivers the DEK to a trusted second factor without the passphrase:

- A RECOVERY slot in the file wraps the DEK to a recovery public key.
- The recovery kit (offline) carries the recovery private key (encrypted) +
  enrollment id.
- `RecoveryVaultKeyPackage = { username, fingerprint, vaultKeyId, enrollmentId,
  generation, keyAlgorithm, encryptedVaultKey }` (server-stored, for the
  "file lost but account intact" path).
- `RecoveryContextCodec` version 2 carries the fingerprint.
- Open: restore the file (backup/copy) -> RECOVERY slot -> HybridDecrypt -> DEK
  -> decrypt. Identity checks are fingerprint checks.

Recovery cannot defeat the zero-knowledge boundary: if every kit, eligible
device, usable header, and backup is lost, the vault is unrecoverable (by
design).

---

## 11. Synchronization protocol

Sync is **per-record encrypted deltas**, re-keyed by fingerprint. The wire shape
is preserved from v0.2; only the key changes.

- Each record exports as an `EncryptedSyncRecord` whose profile AAD is
  `"keystead-sync-profile-v2|{fingerprint}|{secretId}|{revision}"`.
- The server stores per-record encrypted rows keyed by `(account, fingerprint)`.
- Import verifies each row's AAD against the local fingerprint; a row minted for
  a different fingerprint is rejected (cross-vault injection still defeated).
- The server sees only: account, fingerprint (opaque), encrypted rows, row
  counts/sizes. Never passphrase, salt, wrapping key, DEK, or plaintext.

The local one-file format (§4) is decoupled from the sync wire format: sync
transfers records, not the container file.

---

## 12. Single-secret sharing (Landing 3)

Share **one** secret from a vault as a self-contained encrypted string,
unlockable with a temporary passphrase. The recipient needs no vault and no
account.

- **Codec**: `SecretShare`, magic `KSTS\x01`, version 1. The plaintext header
  (KDF params + nonce) is the AAD; the AEAD payload is
  `{shareId, secretType, title, fields{}, sharerNote?, createdAt, expiresAt?}`.
  Encoded `keystead-share:v1:<base64url>`.
- **KDF**: PBKDF2-HMAC-SHA-256 over the temp passphrase, with a **min-strength
  floor** (length + character classes) enforced at creation to bound offline
  brute-force of leaked strings.
- **No vault fingerprint embedded**: a share is intentionally unlinked from the
  vault.
- **Transport = both**: the string is always self-contained (offline-capable);
  optionally uploaded to the server for a short link carrying
  expiry / view-once / revoke. The decryption key never touches the server (the
  temp passphrase, or a key carried in the link fragment, is the only key).
- **Automation-integrated**: automation principals (API tokens / CI) mint shares
  from a vault they hold a vault-key package for, via the server API; the
  server-side share-link hosting and lifecycle live in the automation subsystem
  alongside the automation vault-key-package endpoints. Humans mint via the
  client.
- **Recipient flow**: paste the string (or follow a link -> fetch the blob) ->
  enter the temp passphrase -> view in a short-lived, wiped view.

---

## 13. Security properties (summary)

- **Secrecy at rest**: container AEAD encrypts the entire record set, including
  titles and metadata. No plaintext on disk.
- **Integrity / tamper detection**: the whole-vault AEAD tag authenticates the
  header and the ciphertext; tampering or a wrong passphrase fails cleanly.
- **Offline resistance**: Argon2id (memory-hard) gates passphrase guessing
  against the wrapped DEK.
- **Multi-device without file copy**: a new device bootstraps from a
  server-stored device package and a DEVICE slot; no out-of-band file transfer
  required.
- **Revocation**: dropping a DEVICE/RECOVERY slot protects future access (cannot
  erase already-decrypted records).
- **Zero-knowledge**: the server stores only opaque ciphertext, wrapped key
  packages, share blobs, and fingerprints. No passphrase, salt, wrapping key,
  DEK, or plaintext ever touches the server.
- **Per-record authenticity**: sync rows are self-authenticating and
  fingerprint-bound; cross-vault substitution is rejected.
- **Stable routing**: the fingerprint is stable across DEK rotation (sync routing
  persists); it changes only on passphrase change (re-bind).

---

## 14. Versioning and compatibility

- `formatVersion = 2`; envelope version `1`; AAD label `keystead-secret-record-v3`;
  sync profile `keystead-sync-profile-v2`; fingerprint label
  `keystead-vault-fingerprint-v2`; key-wrap label
  `keystead-vault-key-wrap-v2`; share magic `KSTS\x01` / `keystead-share:v1`.
- **Clean break from v0.2**: a v0.2 folder-vault is rejected with a clear error
  (no read, no importer). This is a major version bump (proposed `1.0.0`;
  final number is the maintainer's call).
- Per the README contributing rule, protocol/format changes require migration and
  compatibility tests: v2 must gracefully reject v0.2 folder vaults, and the
  slot/AAD/fingerprint round-trips are covered by tests.
