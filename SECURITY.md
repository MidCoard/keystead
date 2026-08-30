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

## Scope

This policy applies to the public `keystead` core repository. The
`keystead-server` and `keystead-client` repositories are also public and follow
the same private-disclosure path; each ships its own `SECURITY.md`.

## License

Keystead Core is licensed under the Apache License, Version 2.0. Security fixes
and vulnerability reports accepted by the project are contributed and released
under the same license. See [LICENSE](LICENSE) for the full terms.
