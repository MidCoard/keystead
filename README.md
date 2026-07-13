# Keystead

Keystead is a zero-knowledge password and secret vault ecosystem. It is built
from independent repositories for the encrypted core library, synchronization
server, and desktop client.

## Highlights

- Encrypted local vaults with typed secrets and backups.
- Authenticated device enrollment and bearer-token sessions.
- Encrypted synchronization with revisions, tombstones, and conflict handling.
- Sharing roles, wrapped vault-key packages, and key-generation rotation.
- Short-lived reveal and clipboard workflows with redacted server audit events.

The server stores opaque encrypted data and never decrypts vault secrets or
receives raw vault keys. Mobile clients, biometric integrations, passkeys, and
automatic tombstone deletion are not part of the current release.

## Repositories

- **Keystead Core** — encrypted vault, crypto, schema, backup, and sync library.
- **Keystead Server** — Spring Boot authorization and ciphertext synchronization service.
- **Keystead Client** — Kotlin/JVM Compose Desktop application.

## Status

The current implementation is verified locally across all three repositories:
220 core tests, 247 server tests, and 124 client tests pass with no failures.
