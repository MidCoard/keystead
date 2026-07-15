# Keystead Core Native Memory and Process Hardening Design

## Purpose

Keystead Core will make locked native memory its default storage for owned
secret bytes and will expose an explicit, capability-reporting process
hardening API. The change raises the minimum runtime to Java 25, uses the
standard Foreign Function and Memory (FFM) API, supports Windows, Linux, and
macOS, and fails closed whenever a protection that Core claims to enforce
cannot be established.

This design reduces paging, core-dump, heap-retention, and ordinary debugger
exposure. It does not claim to defeat an administrator, root, the kernel, a
debugger with equivalent privileges, injected code running inside the process,
or copies created by the JVM or a cryptographic provider while a secret is in
active use.

## Approved decisions

- Java 25 LTS is the minimum build and runtime version.
- FFM is used directly; Keystead will not add JNA, JNI, `Unsafe`, or a bundled
  native library.
- Windows, Linux, and macOS are supported in the first release.
- Locked native memory is the Core default, not an optional application
  enhancement.
- Native protection fails closed and never silently falls back to heap memory.
- `SecretMemoryProvider.heap()` remains an explicit compatibility and test
  choice.
- Process-wide hardening is explicit application startup behavior; loading the
  library does not silently alter the host process.
- Anti-debug timing checks, debugger polling, and undocumented platform APIs
  are excluded.

## Java module and native-access boundary

`keystead-core` becomes the named Java module `top.focess.keystead.core`.
Applications using the module path grant native access only to that module:

```text
--enable-native-access=top.focess.keystead.core
--illegal-native-access=deny
-XX:+DisableAttachMechanism
```

Classpath deployments use `--enable-native-access=ALL-UNNAMED`; the README
will recommend the module path because it grants a narrower privilege. Core
checks `Module.isNativeAccessEnabled()` before creating FFM downcall handles and
reports a redacted failure when access is absent. The build uses a reproducible
Java 25 Gradle toolchain rather than depending on a manually installed JDK.

## Public memory API

The existing interfaces remain source-compatible. Their default selection
changes:

```java
public interface SecretMemoryProvider {
    @NonNull SecretMemory protect(byte @NonNull [] value);

    static @NonNull SecretMemoryProvider systemDefault();

    static @NonNull SecretMemoryProvider nativeLocked();

    static @NonNull SecretMemoryProvider heap();
}
```

`systemDefault()` and `nativeLocked()` return the same singleton native
provider. Existing convenience factories and constructors that currently call
`heap()` call `systemDefault()` instead. Constructors that already accept an
explicit provider retain their behavior.

`NativeMemoryProtection.inspect()` performs a one-page allocate/protect/wipe/
release probe and returns a redacted capability report without retaining the
page. Applications may call it before asking a user for a master password.

`NativeMemoryUnavailableException` is an unchecked exception. It may contain
the platform, failed operation, and numeric OS error code. It must not contain
secret bytes, native addresses, usernames, vault identifiers, key identifiers,
or filesystem paths.

## Native allocation and protection

Each secret owns an independent, page-aligned mapping. Mappings are never
pooled or shared between secrets.

### Windows

The backend resolves documented Kernel32 symbols and uses:

1. `VirtualAlloc` with `MEM_RESERVE | MEM_COMMIT` and `PAGE_READWRITE`.
2. `VirtualLock` over the complete page-rounded mapping.
3. Volatile byte writes for destruction.
4. `VirtualUnlock`.
5. `VirtualFree` with `MEM_RELEASE`.

`VirtualLock` failure is fatal. Core does not increase the process working set
automatically because that is a deployment resource decision. Locked pages are
protected from the pagefile, not from an authorized live-memory reader.

### Linux

The backend resolves libc symbols and uses:

1. `mmap` with `PROT_READ | PROT_WRITE` and
   `MAP_PRIVATE | MAP_ANONYMOUS`.
2. `mlock` over the complete mapping.
3. `madvise(..., MADV_DONTDUMP)` over the complete mapping.
4. Volatile byte writes for destruction.
5. `munlock`.
6. `munmap`.

Failure of `mlock` or `MADV_DONTDUMP` is fatal. The exception identifies only
the operation and errno.

### macOS

The backend resolves documented libc symbols and uses:

1. `mmap` with the macOS value of `MAP_ANON`, plus `MAP_PRIVATE` and
   read/write protection.
2. `mlock` over the complete mapping.
3. Volatile byte writes for destruction.
4. `munlock`.
5. `munmap`.

Failure of `mlock` is fatal. macOS does not receive a Linux-style per-mapping
dump-exclusion claim; process-wide core-dump suppression belongs to the process
hardening API.

### FFM safety rules

- Native function descriptors and constants live in platform-specific internal
  backends.
- OS errors are captured immediately after the failing downcall.
- A null native pointer is rejected before reinterpretation.
- Page size and rounded allocation size use checked arithmetic.
- A zero-length logical secret still owns one protected page.
- No `MemorySegment` escapes the provider implementation.
- All access to a live segment occurs while holding the owning
  `SecretMemory` monitor.
- The implementation uses volatile byte stores followed by a full fence when
  wiping native memory so destruction is not an eliminable dead store.

## Ownership state machine

A native secret advances through these internal states:

```text
ALLOCATED -> LOCKED -> DUMP_EXCLUDED (Linux) -> LIVE
LIVE -> WIPED -> UNLOCKED -> RELEASED
```

Windows and macOS omit `DUMP_EXCLUDED`. Input bytes are copied only after every
required protection has succeeded. If construction fails, cleanup proceeds
from the last completed state in reverse order.

`copyBytes` remains synchronized for the complete callback. It copies the
native secret into a temporary heap array, invokes the consumer, and wipes the
array in `finally`. `close` waits for an in-flight callback, is idempotent, and
marks the owner unavailable before releasing native resources.

Cleanup attempts wiping, unlocking, and releasing even when an earlier cleanup
step fails. The first redacted cleanup exception is thrown after all steps have
been attempted; later failures are suppressed. The object remains closed after
such a failure.

The short-lived heap copy is an explicit residual boundary. Existing JCA,
Tink, and Bouncy Castle APIs consume arrays or provider-owned key objects, so
Core cannot claim that active cryptographic operations are heap-free. Existing
temporary-array wiping remains required.

## Process-hardening API

Process hardening is explicit and idempotent:

```java
public final class ProcessHardening {
    public static @NonNull ProcessHardeningReport inspect();

    public static @NonNull ProcessHardeningReport apply(
            @NonNull ProcessHardeningPolicy policy);
}

public enum ProcessHardeningPolicy {
    STRICT
}

public enum HardeningStatus {
    ENFORCED,
    VERIFIED,
    APPLICATION_REQUIRED,
    UNAVAILABLE
}
```

`ProcessHardeningReport` contains the detected platform and one result for
each known control. Result details are fixed, non-sensitive descriptions; they
never contain command lines, paths, account names, native addresses, or secret
metadata.

`STRICT` fails with `ProcessHardeningException` if a code-enforceable required
control is unavailable or cannot be verified. A deployment responsibility is
reported as `APPLICATION_REQUIRED`; Core never converts application
self-attestation into `ENFORCED`.

### Common controls

- Verify Java 25 or later.
- Verify native access for the Keystead module.
- Verify `-XX:+DisableAttachMechanism` is present.
- Verify `-XX:+HeapDumpOnOutOfMemoryError` is not enabled.
- Probe the native locked-memory backend.

### Windows controls

Core applies no process ACL or broad `SetProcessMitigationPolicy` mutation.
Those policies can interfere with the JVM, JIT, service control, monitoring,
and crash handling, and cannot distinguish another process running under the
same account. The report marks dedicated service identity, restrictive process
permissions, crash-dump policy, and administrator separation as application
requirements.

### Linux controls

Core sets and verifies `prctl(PR_SET_DUMPABLE, 0)` and sets/verifies both soft
and hard `RLIMIT_CORE` as zero. The report marks system Yama `ptrace_scope`,
dedicated UID, service sandboxing, and root separation as application
requirements because the library cannot safely set system-wide policy.

### macOS controls

Core sets and verifies both soft and hard `RLIMIT_CORE` as zero. The report
marks Hardened Runtime signing, notarization, removal of `get-task-allow`,
library validation, dedicated identity, and root separation as application
requirements. Keystead does not use undocumented `PT_DENY_ATTACH` behavior.

## Application responsibilities

The README will include a platform matrix that distinguishes Core enforcement
from deployment work.

All applications must:

- invoke strict process hardening before accepting or generating secrets;
- package and launch with the required Java 25 native-access and attach flags;
- use short unlock intervals and close secret owners deterministically;
- avoid administrator/root execution;
- disable or tightly control crash and heap dumps;
- isolate untrusted plugins and agents from the Keystead process.

Windows applications additionally use a dedicated service/user identity and
restrict process access. Linux applications configure Yama and service
sandboxing. macOS applications enable Hardened Runtime and ship without the
debugging entitlement.

## Testing and verification

### Deterministic unit tests

Internal backend interfaces permit fake native operations in tests. Tests
inject failure at allocation, lock, dump exclusion, copying, wiping, unlock,
and release. They assert exact reverse cleanup order, all-stage cleanup after
failure, redacted errors, idempotent close, no access after destruction, and
callback-versus-close atomicity.

Boundary tests cover zero-length secrets, exact page size, first byte over a
page, checked rounding overflow, native null pointers, duplicate hardening
calls, and missing JVM flags.

### Subprocess tests

Process-global controls and launcher flags are tested in child JVMs. Tests run
with and without native access, attach disabling, and heap-dump flags. Linux
children verify `PR_GET_DUMPABLE` and `getrlimit`; macOS children verify
`getrlimit`; Windows children verify real `VirtualLock` allocation and the
honest `APPLICATION_REQUIRED` process-isolation results.

### Cross-platform integration

A GitHub Actions matrix runs Java 25 on Windows, Linux, and macOS. Each job
runs the full Core suite and Spotless with native access explicitly enabled.
Linux additionally verifies locked/dump-excluded mappings where `/proc`
provides authoritative state. macOS verifies locked-page and core-limit calls.
Windows verifies documented allocation/lock/unlock/release calls.

The local platform's complete suite must pass before commit. A platform backend
is not considered verified solely because fake-backend tests pass; all three
matrix jobs are required evidence before the feature is declared complete.

## Compatibility and migration

- Public constructors and factories remain source-compatible.
- Their default memory behavior intentionally changes from heap to native
  fail-closed storage.
- Applications that cannot yet grant native access must explicitly inject
  `SecretMemoryProvider.heap()`; this is documented as reduced protection.
- No persisted vault, backup, recovery, sync, KDF, or encrypted-envelope format
  changes.
- No server persistence or protocol changes.
- Explicit JSpecify annotations remain on all public and internal signatures;
  no package-level nullness defaults are introduced.
- Zero-knowledge behavior and redaction rules remain unchanged.

## Repository and commit discipline

Only Keystead Core, the technical README, Java 25 build/CI configuration, and
the approved design/plan documents are in scope. Server and client repositories
are not inspected or modified. The protected local formatting change in
`VaultServiceTest` remains byte-identical, unstaged, and excluded from every
commit.

## References

- Oracle Java 25 FFM guide:
  https://docs.oracle.com/en/java/javase/25/core/foreign-function-and-memory-api.html
- Java 25 launcher native-access options:
  https://docs.oracle.com/en/java/javase/25/docs/specs/man/java.html
- OpenJDK JEP 454:
  https://openjdk.org/jeps/454
- Microsoft `VirtualLock`:
  https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock
- Linux Yama:
  https://docs.kernel.org/admin-guide/LSM/Yama.html
- Linux `mlock` and `madvise`:
  https://man7.org/linux/man-pages/man2/mlock.2.html
  https://man7.org/linux/man-pages/man2/madvise.2.html
- Apple `mlock` and resource-limit documentation:
  https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/mlock.2.html
  https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/getrlimit.2.html
- Apple Hardened Runtime:
  https://developer.apple.com/documentation/Security/hardened-runtime
