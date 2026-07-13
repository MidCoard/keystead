# Keystead

Keystead is a zero-knowledge password and secret vault made of three cooperating projects:

| Project | Role |
| --- | --- |
| `keystead-core` | Java 21 encrypted-vault library: crypto, secret schemas, local storage, sync, backups, device proofs, and key rotation. |
| `keystead-server` | Spring Boot synchronization and authorization service. It stores opaque ciphertext, metadata envelopes, public keys, and lifecycle records; it does not decrypt vault secrets. |
| `keystead-client` | Kotlin/JVM Compose Desktop application for opening local vaults, editing typed secrets, syncing, device enrollment, reveal/copy workflows, and server authentication. |

The server is not a password-manager UI. Encryption and decryption happen in the core/client boundary; the server coordinates authenticated users, devices, vaults, encrypted records, tombstones, wrapped vault-key packages, memberships, audit events, and sync cursors.

## Features

- Encrypted local vaults with typed secret records: login/password, API token, SSH/GPG keys, certificates, MFA secrets, secure notes, and generic secrets.
- Strict schemas and a public server catalog for required fields, sensitivity, reveal policy, aliases, export names, limits, and taxonomy defaults.
- Bearer access tokens, refresh/revoke/logout-all flows, optional device-bound sessions, and Basic authentication only for explicit local compatibility use.
- Device enrollment using challenge/proof verification and separate proof and wrapping key material.
- Encrypted vault sync with deterministic revision cursors, tombstones, pagination, conflict reporting, and conservative compaction eligibility.
- Encrypted backup archives with integrity checks and safe restore conflict handling.
- Vault membership roles, redacted membership listing, recipient-scoped key packages, and key-generation rotation records.
- Append-only, queryable, redacted audit events.
- Bounded plaintext handling: reveal timers, digest-conditional clipboard clearing, lock/cancel cleanup, and passphrase-protected secure-storage fallback.

## Security boundaries

The server must never receive plaintext secrets, raw vault keys, private device keys, passwords in audit events, or encrypted payload bodies in audit details. Server persistence uses JPA repositories and Flyway migrations; direct JDBC is not part of the application write path. Java production APIs use explicit JSpecify nullness annotations.

Automatic tombstone deletion, passkeys/WebAuthn, biometric OS integrations, true mobile clients, server-side search, and modern-curve OpenPGP remain explicitly deferred design items.

## Build and run

From `D:\IdeaProjects\keystead`:

```powershell
.\gradlew.bat :keystead-core:test --no-daemon --rerun-tasks
```

From `D:\IdeaProjects\keystead-server`:

```powershell
.\gradlew.bat bootRun
.\gradlew.bat spotlessCheck test --no-daemon --rerun-tasks
```

The server defaults to a local H2 database under `data/`. PostgreSQL is available through `compose.yml` and the `postgres` Spring profile.

From `D:\IdeaProjects\keystead-client`:

```powershell
.\gradlew.bat test --no-daemon --rerun-tasks
.\gradlew.bat run
```

The client is currently a desktop JVM target. Android/iOS implementations are not included. This client checkout currently has no Git metadata, so its changes are intentionally not committed.

## Verification snapshot

The latest complete local verification passed with 220 core tests, 247 server tests, and 124 client tests, with zero failures, errors, or skips. See `KEYSTEAD_RELEASE_GATES.local.md` for the reproducible release checklist and the CI workflows in the Git-backed repositories.
