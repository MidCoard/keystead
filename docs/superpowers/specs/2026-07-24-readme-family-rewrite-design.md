# Keystead README Family Rewrite

Date: 2026-07-24

Status: Approved direction

Supersedes: `2026-07-13-readme-redesign-design.md`

## Objective

Rewrite the README in each independent Keystead repository from current source,
tests, and build configuration. Present Keystead as one product family without
blurring the responsibility or audience of its three repositories.

The documentation must use public GitHub links and must not expose local paths,
worktrees, handoff files, or untracked design notes.

## Product identity and repository map

Keystead is a local-first, zero-knowledge secret-vault system composed of three
independently versioned repositories:

| Repository | Audience | Responsibility |
| --- | --- | --- |
| Keystead Core | Java users, security reviewers, and contributors | Cryptography, typed secrets, vault persistence, encrypted sync and backup formats, recovery and rotation primitives, native secret memory, and process-hardening APIs |
| Keystead Client | Desktop users | Local vault UI, secret workflows, server connectivity, collaboration and recovery UX, and OS-native device-identity storage |
| Keystead Server | Self-hosters and operators | Accounts, verified devices, opaque encrypted-row synchronization, wrapped-key distribution, collaboration, rotation coordination, recovery coordination, and JPA persistence |

Every README will introduce its own repository first, then include a compact
map with public links to the other two repositories.

## Security narrative

The README family will describe security as a composed product capability:

- Core uses Java 25 FFM for fail-closed, page-locked native secret memory by
  default. It exposes explicit inspection and process-hardening APIs because
  process-wide mutations must remain under application and deployment control.
- Client protects device wrapping and proof private keys through Windows DPAPI,
  macOS Keychain, or Linux Secret Service. Native availability is probed and
  failure never silently selects a weaker fallback.
- Server stores ciphertext, encrypted profiles, revisions, membership state,
  public keys, and client-wrapped key packages. It does not receive plaintext
  secret fields, raw vault keys, or device private keys.

Limits will be stated alongside the guarantee they qualify. Locked memory and
dump controls reduce paging and crash-dump exposure but cannot defeat malware,
a debugger, or another actor that already controls the live process.
OS-user-protected storage is not a claim of Windows Hello, Touch ID, or other
biometric-gated release. Zero knowledge protects secret contents, not account,
membership, timing, revision, or ciphertext-size metadata.

The README files will not compare Keystead with other products and will not
claim an independent security audit.

## README-specific structure

### Keystead Core

Keep this README as the detailed technical reference:

1. library identity and ecosystem map;
2. architecture and vault-operation flow;
3. typed secret model and generators;
4. cryptography, algorithm abstractions, and key lifecycle;
5. native memory and process hardening;
6. persistence, crash recovery, sync, backup, collaboration, and recovery
   primitives;
7. public API example and integration responsibilities;
8. module structure, JSpecify contracts, build, verification, and contribution
   rules;
9. security guarantees and limits.

### Keystead Client

Write for desktop users:

1. application identity and ecosystem map;
2. capabilities and first-run/daily workflow;
3. local encryption and zero-knowledge sync;
4. supported secret types and generators;
5. devices, OS-native secure storage, reveal, clipboard, and lock behavior;
6. sharing, staged rotation, backup, and both recovery paths;
7. installation/run requirements and verification;
8. current platform and threat-model limits.

### Keystead Server

Write for self-hosters and operators:

1. service identity and ecosystem map;
2. user-visible capabilities;
3. zero-knowledge and metadata boundary;
4. authentication, verified devices, sync, collaboration, staged rotation,
   automation, audit, and recovery;
5. JPA-only persistence and Flyway ownership;
6. H2 evaluation and PostgreSQL deployment;
7. configuration, operational responsibilities, and verification;
8. current scaling and product limits.

## Accuracy and maintenance rules

- Use JDK 25 wherever the build toolchain requires it.
- Do not publish fixed test counts unless they are generated and guaranteed to
  remain current; describe suite coverage instead.
- Distinguish an implemented capability from its repository location. In
  particular, do not describe OS-native protection as absent merely because
  credential-store adapters live in Client.
- Preserve the zero-knowledge boundary, JPA-only server persistence, explicit
  JSpecify contracts, and fail-closed native-memory default.
- Keep commands repository-relative and platform variants accurate.
- Verify links, local-path absence, Markdown whitespace, and relevant build
  commands before committing README-only changes independently in each Git
  repository.
