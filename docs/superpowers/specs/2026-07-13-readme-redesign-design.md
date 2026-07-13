# Keystead README Redesign

Date: 2026-07-13
Status: Approved design

## Purpose

Give each independent repository a README written for its real audience while
keeping the three projects recognizable as one Keystead ecosystem.

The documentation must explain the implemented system deeply and honestly. It
must not expose local filesystem paths, internal handoff notes, worktree state,
or claims that are stronger than the current source and verification evidence.

## Repository audiences

### Keystead library

The `keystead` repository targets technical library users and contributors.
Its README will explain:

- the library's responsibilities and public integration boundary;
- vault and record architecture;
- encryption, authenticated metadata, key derivation, and key rotation;
- secret schemas and typed record handling;
- backup, restore, synchronization, tombstones, and conflict semantics;
- device proof and wrapped vault-key provisioning;
- crash consistency, failure behavior, nullness, and testing;
- source layout, build commands, and contribution expectations;
- a candid maturity and competitive-position analysis.

The server and client receive only short contextual descriptions.

### Keystead Server

The `keystead-server` repository targets end users and self-hosting operators.
Its README will explain:

- why the server exists and what benefits it provides;
- the zero-knowledge boundary and server-visible data;
- accounts, bearer sessions, devices, sync, sharing, rotation, and auditing;
- H2 and PostgreSQL deployment paths;
- essential configuration and verification commands;
- operational and product limitations;
- a short comparison focused on self-hosting and privacy.

Internal repository design details will appear only where they affect safe
operation.

### Keystead Client

The `keystead-client` repository targets end users. Its README will explain:

- what the desktop application is for;
- first-run and daily workflows;
- supported secret types;
- local vault, server login, device enrollment, synchronization, backup,
  reveal, clipboard, and lock behavior;
- secure-storage behavior and current desktop platform scope;
- run and test commands;
- a short comparison focused on daily usability and current ecosystem gaps.

The README will not discuss the local checkout's Git metadata.

## Comparison method

Comparisons will distinguish architecture from product maturity. They will use
neutral language and current official product documentation as the source for
external claims.

Comparison set:

- Bitwarden: zero-knowledge synchronization and mature self-hosting ecosystem.
- 1Password: managed service, device-local Secret Key design, and mature client
  ecosystem.
- KeePassXC: local encrypted database with external file synchronization and
  mature browser/desktop integrations.
- Proton Pass: consumer-focused end-to-end encryption, metadata protection,
  cross-platform clients, aliases, and sharing.

Keystead's implemented differentiators will be described as typed schema
ownership, explicit encrypted-row protocol contracts, deterministic revision
and tombstone semantics, separately proven device keys, crash-journaled local
key rotation, and a deliberately narrow JPA-backed zero-knowledge server.

The README will state that Keystead does not yet match established products in
browser autofill, mobile applications, passkeys, independent audits, polished
recovery, production operating history, or integration breadth.

Official comparison references:

- https://contributing.bitwarden.com/architecture/security/principles/servers-are-zero-knowledge/
- https://1password.com/files/1Password-White-Paper.pdf
- https://keepassxc.org/docs/
- https://proton.me/pass/security

## Presentation rules

- Use normal GitHub README structure and repository-relative commands.
- Lead with identity and value before implementation details.
- Prefer diagrams or compact tables only where they clarify architecture or
  comparison.
- Separate verified capabilities, security invariants, and future work.
- Avoid marketing superlatives and unsupported security guarantees.
- Do not copy long passages from competitor documentation.
- Keep the server and client READMEs substantially shorter than the library
  README.

## Verification

Before committing README changes:

- scan all three files for local absolute paths and worktree-only language;
- check every Keystead feature claim against current source or test evidence;
- check competitor claims against the official references above;
- run Markdown/diff whitespace checks;
- commit only the library and server READMEs because those repositories have
  Git metadata;
- update the client README in place without creating Git metadata.
