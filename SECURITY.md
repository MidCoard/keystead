# Security Policy

Keystead is a zero-knowledge vault: the server never sees plaintext secrets or
vault keys, and the core library is the authoritative implementation of that
cryptographic contract. This document covers reporting vulnerabilities and the
checks that must pass before any release.

## Reporting a vulnerability

Do **not** open a public issue for a security vulnerability. Report it privately
so a fix can be prepared and released before disclosure:

- Open a private security advisory:
  <https://github.com/MidCoard/keystead/security/advisories/new>
- Or contact the project owner directly through a private channel.

Please include:

- A description of the issue and its security impact.
- The affected component (`keystead-core`, `keystead-server`, or
  `keystead-client`) and, if known, the symbol, route, or migration involved.
- A minimal reproduction or proof of concept.
- Any suggested remediation.

The project owner will acknowledge receipt and coordinate a fix and disclosure
timeline. Vulnerabilities must be reported privately before any public
disclosure.

## Pre-release security checklist (mandatory)

Before tagging a release or publishing artifacts, every item below must pass:

- [ ] All three test suites are green on their CI lanes:
      core, server (H2 + PostgreSQL), client.
- [ ] No plaintext secret, raw token, or wrapped vault key is stored, logged,
      audited, or returned by any code path (redaction review).
- [ ] The zero-knowledge contract holds: the server stores only opaque
      ciphertext and wrapped key packages; no vault key material touches the
      server.
- [ ] JPA is the only database access path on the server (no raw JDBC); the
      `NoDirectJdbcAccessTest` architecture check passes.
- [ ] Flyway migrations are forward-only and run cleanly on both H2 and
      PostgreSQL.
- [ ] Audit events are durable and tamper-evident: when audit signing is
      enabled, every persisted event carries a reproducible HMAC signature.
- [ ] The audit-signing key (when configured) is rotated as part of the release
      and never committed to the repository.
- [ ] CodeGraph indexes are fresh for each repository (no stale-symbol
      surprises in review).
- [ ] Dependency versions are pinned and a dependency audit shows no known
      high-severity advisories.

## Scope

This policy applies to the public `keystead` core repository. The
`keystead-server` and `keystead-client` repositories are private and follow the
same pre-release checklist; their release artifacts are for internal use.

## License

Keystead Core is licensed under the Apache License, Version 2.0. Security fixes
and vulnerability reports accepted by the project are contributed and released
under the same license. See [LICENSE](LICENSE) for the full terms.
