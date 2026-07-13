# Zero-Knowledge Account and Vault Recovery Design

## Purpose

Keystead recovery restores two independent capabilities:

1. access to the server account after the login password is lost; and
2. access to vault keys after usable local device key material is lost.

Recovery must not make the server capable of decrypting vault data. A user may
recover through either an offline recovery kit or approval from an existing
verified device. If neither authority remains, Keystead cannot recover the
vaults. The product must state that outcome plainly rather than introduce an
administrator bypass.

The server password, local device-storage passphrase, device private keys, and
vault keys remain distinct. Recovery replaces credentials; it never reveals an
old password or passphrase.

## Shared protocol primitives

The core library defines versioned, canonical encodings for recovery public
keys, encrypted recovery-private-key envelopes, vault recovery packages, device
approval requests, approval signatures, and recovery completion manifests. All
new public Java APIs use explicit JSpecify nullness annotations.

Cryptographic operations reuse the project's approved AEAD, hybrid-encryption,
signature, key-identifier, and secure-random boundaries. Domain labels separate
account authentication, private-key-envelope encryption, package encryption,
checksums, and request signatures. Decoders reject unknown versions,
non-canonical values, invalid lengths, trailing bytes, algorithm substitution,
and identifier mismatches.

## Offline recovery kit

### Enrollment

The client generates a 256-bit random recovery secret and a dedicated recovery
wrapping key pair. The printable recovery kit contains a format version,
enrollment identifier, recovery generation, recovery secret, and checksum. It
does not contain the username, password, vault keys, or device private keys.

The recovery secret derives two domain-separated values:

- a high-entropy account recovery credential; and
- an AEAD key that encrypts the recovery wrapping private key.

The client uploads only:

- a one-way password-encoder representation of the account recovery credential;
- the recovery wrapping public key;
- the encrypted recovery wrapping private-key envelope; and
- version, algorithm, generation, and lifecycle metadata.

For each vault the user can currently access, a client holding that vault key
creates an opaque package encrypted to the recovery public key. The package is
bound to user, vault, vault-key identifier, recovery enrollment, and recovery
generation. The server validates identifiers and authorization but cannot open
the package.

Recovery kit regeneration creates a new generation. The old kit remains valid
until the new kit and required vault packages have been verified and committed;
commit then invalidates the old generation atomically.

### Recovery

Recovery starts with a generic challenge endpoint that does not disclose whether
an account or enrollment exists. The client derives and submits the account
recovery credential over the authenticated TLS channel. The server verifies its
stored one-way representation and issues a short-lived, single-purpose recovery
session.

The restricted session may download the encrypted recovery-private-key envelope
and authorized opaque vault packages. The client derives the envelope key,
decrypts the recovery private key locally, opens each vault package locally, and
verifies every embedded identifier before continuing.

Only after successful local decryption does the client submit a completion
manifest containing a new server password, new verified device public keys, and
new device packages for recovered vault keys. Server completion is transactional:
it changes the password hash, increments the token version, revokes refresh
tokens, enrolls the replacement device, consumes the recovery generation, writes
the new opaque packages, and records redacted audit events. A failed or abandoned
local decryption does not consume the kit.

Successful use requires generation of a replacement kit before recovery is
considered fully healthy. The UI may allow the user to finish account access
first, but it must continue to show recovery setup as incomplete.

## Verified-device approval

A new client generates temporary request-signing material plus its intended
device signing and wrapping public keys. It submits a recovery request and shows
a short fingerprint derived from the canonical request.

An existing verified, non-revoked device lists pending requests for its own
account. After the user compares the fingerprint, the existing device signs the
canonical request and uploads the approval. The server verifies the signature,
device state, request expiry, account binding, and single-use nonce before
issuing the same restricted recovery session.

The approving device creates current vault-key packages directly for the new
device wherever it has the required vault key. Missing vaults do not cause the
server to learn keys: those vaults remain visibly pending until another
authorized device or vault manager provides a current package.

Completion resets the server password, revokes prior sessions, and enrolls the
new device transactionally. Approval never transfers an existing device private
key and never grants access to a vault for which no authorized client can create
a package.

## Server persistence and boundaries

Persistence remains JPA-only with Flyway-managed schema changes. New entities
represent recovery enrollments/generations, opaque vault recovery packages,
pending device-approval requests, approvals, and expiring recovery sessions.
Repositories use normal JPA mappings and constraints; no direct JDBC or native
SQL persistence path is introduced.

Stored state includes hashes, public keys, ciphertext, identifiers, expiries,
attempt counters, and lifecycle state. It never includes recovery secrets,
recovery private keys in plaintext, device private keys, unwrapped vault keys,
new plaintext passwords, or local storage passphrases.

Recovery endpoints use generic not-found/authentication responses, bounded
attempts, rate limits, single-use challenges, short expiries, transactional
compare-and-set state transitions, and redacted audit metadata. Concurrent
completion accepts exactly one winner. Expired, consumed, superseded, or
algorithm-mismatched material is rejected.

## Rotation and collaboration interaction

Vault-key rotation creates a new recovery package for every active recovery
enrollment that should retain access. A package for an old vault-key identifier
cannot satisfy recovery coverage for the new generation. Removing a member does
not erase historical keys they already possessed; removal-triggered rotation
omits that member's devices and recovery public key from the new generation.

Account recovery can complete even when some shared-vault packages are missing,
but the response and UI must report those vaults as pending rather than implying
that they were recovered. Package creation remains a client-side operation by a
party that already holds the vault key.

## Client experience

The client provides separate actions for generating/replacing a recovery kit,
recovering with a kit, requesting verified-device approval, approving a request,
and completing a password reset. Kit creation requires an explicit confirmation
that the user stored it offline; Keystead never uploads the printable kit.

Screens distinguish server-account recovery, device enrollment, and per-vault
key-package coverage. Error messages disclose enough to act locally but do not
turn unauthenticated endpoints into account-enumeration oracles. Secrets and
decrypted package content are never written to logs, clipboard history, crash
reports, or persisted UI state.

## Verification

Core tests cover canonical encoding, domain separation, package binding,
malformed input, tampering, wrong secrets/keys, stale key identifiers, and
defensive secret handling.

Server tests cover JPA constraints and every lifecycle transition, generic
responses, rate/attempt limits, expiry, concurrent completion, session and token
revocation, redacted audits, stale generations, unauthorized package access,
and transaction rollback. Tests also prove that persistence contains only the
specified public, hashed, or encrypted material.

Client tests cover kit round trips, failure-before-consumption, request
fingerprints, approval signatures, local package decryption, replacement-device
enrollment, missing-vault reporting, secret redaction, and resumable completion.
End-to-end tests exercise both authorities from enrollment through password
reset and opening a recovered vault, including the permanent-loss outcome when
neither authority exists.
