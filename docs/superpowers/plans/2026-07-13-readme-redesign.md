# Keystead README Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the three minimal READMEs with audience-specific, evidence-backed documentation that explains Keystead deeply and compares it honestly with established password managers.

**Architecture:** The library README is the authoritative technical narrative for contributors and integrators. Server and client READMEs are shorter end-user documents that explain value, workflows, setup, privacy boundaries, and limitations while mentioning the other repositories only briefly.

**Tech Stack:** GitHub-flavored Markdown, Java 21/Gradle, Spring Boot, Kotlin/JVM Compose Desktop.

## Global Constraints

- Do not include absolute local filesystem paths, worktree state, or internal handoff details.
- Use only implemented Keystead capabilities proven by current source/tests.
- Use official Bitwarden, 1Password, KeePassXC, and Proton Pass documentation for external claims.
- Separate architecture differences from product maturity.
- Keep server and client READMEs substantially shorter than the library README.
- Commit only in repositories with Git metadata; do not initialize Git for the client.

---

### Task 1: Technical library README

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: `KEYSTEAD_LLD_FEATURES.local.md`, current core source/tests, and the approved README design.
- Produces: the authoritative technical description used by library users and contributors.

- [ ] **Step 1: Replace the README with the technical narrative**

Use this exact section order:

```markdown
# Keystead Core
project identity and intended audience

## Why Keystead Core exists
## Architecture
## How a vault operation works
## Capabilities
## Secret type model
## Cryptography and key lifecycle
## Synchronization model
## Backup and crash recovery
## Security model and threat boundaries
## Public API example
## Repository structure
## Build and verification
## Comparison with established products
## Honest project assessment
## Contributing
```

The architecture section must distinguish API/service, cryptography, encrypted
model, and storage boundaries. The operation flow must cover derive/unlock,
decrypt in caller scope, modify typed data, re-encrypt with authenticated
metadata, and durably commit. The assessment must list both strengths and
missing production capabilities.

- [ ] **Step 2: Verify technical claims**

Run:

```powershell
rg -n "class |record |interface |enum " keystead-core/src/main/java
rg -n "rotation|journal|tombstone|Backup|DeviceVaultKeyPackage|SecretTypeCatalog" keystead-core/src/main keystead-core/src/test
```

Expected: every named type, flow, and invariant in the README maps to current source or tests.

- [ ] **Step 3: Verify Markdown and privacy**

Run:

```powershell
rg -n "D:\\|IdeaProjects|worktree|handoff|no Git metadata" README.md
git diff --check -- README.md
```

Expected: the first command has no matches and the diff check succeeds.

- [ ] **Step 4: Commit the library README**

```powershell
git add README.md
git commit -m "Write technical Keystead Core README"
```

### Task 2: End-user server README

**Files:**
- Modify: `../keystead-server/README.md`

**Interfaces:**
- Consumes: current server configuration, controllers, migrations, and security tests.
- Produces: an operator-focused explanation of the self-hosted zero-knowledge server.

- [ ] **Step 1: Replace the server README**

Use this exact section order:

```markdown
# Keystead Server
end-user identity and reason to run it

## What the server gives you
## How it protects your vault
## How synchronization works
## Accounts, devices, and sharing
## Deployment
## Configuration
## Verification
## How it compares
## Current limitations
```

Keep implementation details subordinate to operational meaning. Include H2
development and PostgreSQL deployment commands, bearer-auth production
behavior, server-visible versus encrypted data, and an honest statement that
this is not yet a turnkey audited service.

- [ ] **Step 2: Verify server claims and commands**

Run:

```powershell
rg -n "RequestMapping|ConfigurationProperties|datasource|basic-auth-enabled" src/main
.\gradlew.bat spotlessCheck test --no-daemon
```

Expected: documented endpoints/configuration exist and the complete server gate passes.

- [ ] **Step 3: Check and commit**

```powershell
rg -n "D:\\|IdeaProjects|worktree|handoff|no Git metadata" README.md
git diff --check -- README.md
git add README.md
git commit -m "Write end-user Keystead Server README"
```

### Task 3: End-user desktop client README

**Files:**
- Modify: `../keystead-client/README.md`

**Interfaces:**
- Consumes: current Compose UI, server session, device enrollment, local sync, backup, plaintext lifecycle, and secure-storage behavior.
- Produces: an end-user desktop guide without repository-internal commentary.

- [ ] **Step 1: Replace the client README**

Use this exact section order:

```markdown
# Keystead Client
end-user product identity

## What you can do
## How your data is protected
## Typical workflow
## Supported secret types
## Synchronization and devices
## Reveal, clipboard, and local storage safety
## Run the desktop app
## Verification
## How it compares
## Current limitations
```

Explain practical user flows and desktop scope. State clearly that browser
autofill, mobile applications, passkeys, native OS credential-store adapters,
and independent audits are not current capabilities.

- [ ] **Step 2: Verify client claims and commands**

Run:

```powershell
rg -n "fun main|SecretType|RevealLifecycle|ClipboardLifecycle|SecureStorage|DeviceEnrollment|LocalVaultSync" src/main src/test
.\gradlew.bat test --no-daemon
```

Expected: all documented workflows exist and the client suite passes.

- [ ] **Step 3: Check the uncommitted client README**

```powershell
rg -n "D:\\|IdeaProjects|worktree|handoff|no Git metadata" README.md
```

Expected: no matches. Do not create Git metadata or a commit.

### Task 4: Cross-repository comparison and consistency review

**Files:**
- Review: `README.md`
- Review: `../keystead-server/README.md`
- Review: `../keystead-client/README.md`

**Interfaces:**
- Consumes: all three completed READMEs and official competitor documentation.
- Produces: a consistent, non-misleading final documentation set.

- [ ] **Step 1: Check comparison claims**

Confirm only these externally sourced facts are used:

```text
Bitwarden: zero-knowledge server design and self-hosting.
1Password: managed ecosystem and locally created Secret Key architecture.
KeePassXC: offline KDBX database, external file sync, browser integration.
Proton Pass: end-to-end encryption including metadata and cross-platform consumer applications.
```

- [ ] **Step 2: Check repository identity and duplication**

Read the files side by side. The library README must contain the deep
architecture analysis; server/client comparisons must each fit in a compact
table or short section and focus on their end-user role.

- [ ] **Step 3: Final whitespace and status checks**

```powershell
git -C ..\keystead diff --check
git -C ..\keystead-server diff --check
git -C ..\keystead status --short
git -C ..\keystead-server status --short
```

Expected: no README whitespace errors; only explicitly preserved unrelated
files remain dirty.
