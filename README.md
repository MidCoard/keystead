# Keystead Core

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

Keystead Core is the Java 25 cryptographic and local-vault library used by the Keystead ecosystem. It owns the parts that must remain independent from any desktop UI or server: vault files, key derivation and wrapping, authenticated record encryption, typed secret schemas, encrypted synchronization rows, portable backups, one-off shares, secret-memory handling, and process-hardening helpers.

Core has no accounts, HTTP client, team vaults, members, roles, invitations, persistent server devices, biometric implementation, DPAPI integration, or server database model.

## Ecosystem boundary

| Project | Responsibility |
| --- | --- |
| **Keystead Core** | Local vault format, cryptography, encrypted record import/export, backup, access-request codecs, sharing, and memory protection |
| **Keystead Client** | Desktop UI, local vault selection, Windows Hello local login, account sessions, sync validation, approval, and restore workflows |
| **Keystead Server** | Account sessions, one opaque encrypted record stream per account, short-lived access-request relay, one-off share hosting, and redacted audit events |

One Keystead account represents one personal encrypted record stream. The server does not receive a raw data-encryption key (DEK), vault master password, local-login private key, biometric data, or plaintext secret.

## Vault model

A Keystead vault is one encrypted `.kvault` file. It is not JSON and the complete file is not the server sync format.

- Creation generates a random DEK.
- The master password is processed with Argon2id and wraps the DEK; it is not used directly to encrypt records.
- Each record is independently encrypted and authenticated with the DEK and record-specific associated data.
- The plaintext header contains format and routing metadata plus wrapped key slots, never a raw DEK.
- Closing `VaultHandle` destroys the handle's live key material and releases its file lock.
- `OneFileVaultStore` uses a sibling lock file, recovery journal, and atomic replacement for committed mutations.

`VaultService` is the entry point for creating and opening vaults. `VaultHandle` exposes typed secret operations, encrypted record export/import, local unlock-slot changes, backup creation, and generic public-key wrapping of the active DEK.

## Local login and generic recipient keys

Some public Core names contain `Device`, including `DeviceKeyPair`, `DeviceVaultKeyPackage`, `SlotType.DEVICE`, `addDeviceKey`, and `provisionVault`. In Core these are generic hybrid recipient-key primitives retained as part of the current API and file format. They do not define a persistent server device identity.

Keystead Client uses these primitives in two separate ways:

- **Local login:** one optional local private key can be protected by Windows Hello or by a separate local passphrase. A local `DEVICE` slot wraps the same vault DEK so the local vault can open without typing its master password. This key is never registered with the server.
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

Synchronization moves `EncryptedSyncRecord` values, not vault headers and not decrypted secrets.

- `VaultHandle.exportRecordsSince(revision)` exports encrypted record revisions and authenticated tombstones.
- `VaultHandle.importRecordsWithReport(records)` authenticates downloaded rows with the open vault's DEK and reports imported, skipped, conflicting, and rejected rows.
- A row encrypted with another DEK fails local authentication and must not be stored in the local vault.
- The transport can be append-only. Core does not require the server to understand record plaintext or possess the DEK.
- The server cannot cryptographically prove that all clients used the same DEK; the receiving client is the enforcement point.

The current server stores one append-only personal record event stream per account. Team and collaboration synchronization are not part of the current model.

## Portable backup

`FullVaultBackupService` creates and restores complete password-protected backups. A portable backup contains enough encrypted material to create a new local vault without the original vault file, original master password, server, or local-login key.

Restore requires:

- the `.ksbackup` file;
- its independent backup password;
- a new target `.kvault` path that does not already exist;
- a new local master password.

Restore does not silently overwrite an existing target.

## Typed secrets and generators

Core provides dedicated payload formats for login passwords and secure notes plus schemas for structured secret types. Plaintext enters through mutable `SecretBuffer` values and is exposed through short-lived view callbacks where possible.

Generators cover passwords, API tokens, SSH keys, OpenPGP keys, MFA seeds and TOTP values, and X.509 certificate bundles. Generated private material uses closeable or mutable containers so callers can destroy it deterministically.

## One-off sharing

`ShareService` creates a self-contained `keystead-share:v1` encrypted string protected by an independent temporary passphrase. The recipient needs neither an account nor a vault. Keystead Server may host this opaque string with expiry and optional burn-after-reading behavior, but Core performs the encryption and decryption.

## Cryptography

The current implementation uses:

| Purpose | Implementation |
| --- | --- |
| Master-password KDF | Argon2id |
| Record and metadata encryption | AES-256-GCM with domain-separated associated data |
| Recipient/exchange wrapping | Google Tink ECIES P-256, HKDF-HMAC-SHA256, AES-128-GCM |
| Password hashes and fingerprints | Domain-separated SHA-256-based constructions where specified by the format |
| SSH/OpenPGP/X.509 generation | Bouncy Castle |

Google Tink depends on protobuf for its own key serialization. Keystead does not use protobuf as its client/server wire protocol. The `protobuf-java` `sun.misc.Unsafe` warning on JDK 25 is a transitive dependency compatibility warning; removing protobuf without replacing Tink would remove the active hybrid-encryption implementation.

## Secret memory and process hardening

Core provides locked native-memory backends and process inspection/hardening helpers. These controls reduce accidental persistence and post-crash disclosure; they cannot protect plaintext from code, malware, a debugger, or a privileged process that already controls the live application.

Applications must:

- grant native access to `top.focess.keystead.core` or the unnamed module;
- decide whether native-memory failure should be fatal or whether an explicit heap fallback is acceptable;
- keep plaintext callbacks short and wipe caller-owned arrays;
- apply strict process hardening only at an appropriate application lifecycle boundary;
- understand that Windows Hello is implemented in Keystead Client, not Core, and is only a local convenience gate.

## Build and test

Requirements:

- JDK 25 (Adoptium toolchain in the Gradle build);
- Gradle wrapper included in the repository.

Run all named-module and classpath-consumer tests:

```powershell
.\gradlew.bat check --no-daemon
```

Publish the current snapshot to Maven Local for Client and Server development:

```powershell
.\gradlew.bat :keystead-core:publishToMavenLocal --no-daemon
```

Dependency coordinates:

```kotlin
implementation("top.focess:keystead-core:0.4.4-SNAPSHOT")
```

The module name is `top.focess.keystead.core`. Its exported packages are `access`, `aigc`, `crypto`, `generator`, `memory`, `model`, `security`, `service`, `share`, and `store` under `top.focess.keystead`.

## Security limits

- A compromised live process can observe plaintext while the vault is open.
- A user who can satisfy the configured Windows Hello or local-login-passphrase check can use that local unlock slot.
- Revoking a local slot does not erase plaintext or keys already copied by an attacker.
- An append-only server can retain ciphertext and traffic metadata, including account identity, vault fingerprint, record identifiers, revisions, timestamps, and sizes.
- Losing every usable local vault and portable backup permanently loses access to opaque server records.
- The API and on-disk formats are still under active development; pin exact versions.
