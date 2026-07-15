# Keystead Core Native Memory and Process Hardening Design

## Purpose

Keystead Core will make locked native memory its default storage for owned
secret bytes and will expose an explicit, capability-reporting process
hardening API. The change raises the minimum runtime to Java 25, uses the
standard Foreign Function and Memory (FFM) API, supports Windows, Linux, and
macOS, and fails closed whenever a protection that Core claims to enforce
cannot be established.

This design reduces paging and heap retention on every supported platform,
excludes Linux mappings from ordinary core dumps, reduces same-UID `ptrace`
exposure on Linux, and disables JVM serviceability attach when the effective
HotSpot option is set. Windows and macOS native-debugger isolation remains a
deployment responsibility. The design does not claim to defeat an
administrator, root, the kernel, a debugger with equivalent privileges,
injected code running inside the process, or copies created by the JVM or a
cryptographic provider while a secret is in active use.

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
reports a redacted failure when access is absent. The module descriptor exports
all existing public packages (`aigc`, `crypto`, `generator`, `memory`, `model`,
`recovery`, `service`, and `store`) and declares the current Tink and Bouncy
Castle modules. It uses `requires transitive org.jspecify` because JSpecify
annotations occur in public signatures, plus `java.management` and
`jdk.management` for effective HotSpot-option inspection.

The build pins the Temurin vendor and Java 25 feature release, auto-provisions
it through a Gradle toolchain resolver, records the resolved runtime in test
diagnostics, and pins an exact Temurin 25 release in CI. "Reproducible" here
means no dependency on a manually installed JDK and a consistent vendor/feature
release; it is not a bit-for-bit promise across later Temurin security updates.
Tink 1.22.0's automatic module name `com.google.crypto.tink` is pinned and
asserted by a build test. A dependency upgrade that changes it must deliberately
update `module-info.java`. Compile/run fixtures cover both named-module and
classpath consumers.

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

`systemDefault()` and `nativeLocked()` return the same safely lazy singleton
native provider. Obtaining the provider has no native side effects; platform
resolution occurs when `protect(...)` is first used or capability inspection is
requested. During `protect(...)`, missing native access, an unsupported
OS/architecture tuple, a symbol/layout mismatch, and an allocation quota
failure are converted to `NativeMemoryUnavailableException` without poisoning
class initialization. Inspection reports the same conditions as capability
data under the contract below. `systemDefault()` never selects heap implicitly.
Existing convenience factories and constructors that currently call `heap()`
call `systemDefault()` instead. Constructors that already accept an explicit
provider retain their behavior.

`NativeMemoryProtection.inspect()` is fully defined as:

```java
public final class NativeMemoryProtection {
    public static @NonNull NativeMemoryProtectionReport inspect();
}
```

`NativePlatform` has stable values `WINDOWS_X86_64`, `LINUX_X86_64`,
`LINUX_AARCH64`, `MACOS_X86_64`, `MACOS_AARCH64`, and `UNSUPPORTED`.
`NativeProtectionControl` has stable ordered values
`PLATFORM`, `NATIVE_ACCESS`, `ABI_LAYOUTS`, `SYMBOLS`, `ALLOCATION`,
`PAGE_LOCK`, `DUMP_EXCLUSION`, `WIPE`, `PAGE_UNLOCK`, and `RELEASE`.
`NativeProtectionStatus` has `VERIFIED`, `UNAVAILABLE`, `FAILED`,
`NOT_APPLICABLE`, and `NOT_ATTEMPTED`. Each `NativeProtectionResult` has a
non-null control/status/fixed detail code and a `@Nullable Long osErrorCode`.

`NativeMemoryProtectionReport` contains a non-null platform and an immutable,
defensively copied `List<@NonNull NativeProtectionResult>` with exactly one
entry per control in enum order. It exposes
`@Nullable NativeProtectionResult result(@NonNull NativeProtectionControl
control)`. All reference-bearing constructor, accessor, collection element,
and internal signatures carry explicit JSpecify annotations. Equality and hash
code are value based; `toString` is fixed-format and redaction-safe. Consumers
must ignore future controls they do not understand.

`inspect()` performs a one-page allocate/protect/wipe/release probe without
retaining the page. A missing prerequisite marks that control `UNAVAILABLE`
and dependent operations `NOT_ATTEMPTED`; an OS operation failure is `FAILED`;
Windows/macOS dump exclusion is `NOT_APPLICABLE`. The result is a transient
capability snapshot, not a reservation or a guarantee that a later
page-per-secret allocation will fit the process lock quota. Applications may
call it before asking a user for a master password.

Capability failure is data for `inspect()`: the method returns a report and
does not throw `NativeMemoryUnavailableException` for unsupported platform,
native-access, symbol/layout, quota, or probe-operation failure. In contrast,
`nativeLocked().protect(...)` and every convenience default throw the redacted
exception when required protection cannot be established. Unexpected Java
programming errors remain ordinary runtime errors and are not converted into a
capability result.

`NativeMemoryUnavailableException` is an unchecked exception. It may contain
the platform, failed operation, and numeric OS error code. It must not contain
secret bytes, native addresses, usernames, vault identifiers, key identifiers,
or filesystem paths. Public errors never retain raw FFM/native exceptions as a
cause or suppressed exception: causes and suppressed failures are rebuilt from
fixed operation identifiers and numeric OS codes only. The same rule applies to
reports and log-safe serialization.

## Native allocation and protection

Each secret owns an independent, page-aligned mapping. Mappings are never
pooled or shared between secrets.

### Supported ABI tuples

The first release supports 64-bit HotSpot-compatible JVMs on Windows x86-64,
Linux x86-64 and AArch64, and macOS x86-64 and AArch64. Every other OS,
architecture, data model, or JVM family fails closed as unsupported. Each of
the five claimed tuples is exercised in CI.

All descriptors use `Linker.canonicalLayouts()` for C `int`, `long`, `size_t`,
and `void*`. POSIX `off_t` is an asserted signed 64-bit layout on the supported
tuples. Windows `DWORD` and `BOOL` use the 32-bit C `int` carrier and `SIZE_T`
uses the pointer-width `size_t` carrier. Linux/macOS `rlim_t` is asserted as an
unsigned 64-bit value represented by the `long` carrier; `struct rlimit` is an
explicit naturally aligned two-field layout of exactly 16 bytes. Startup fails
closed if any size/alignment assertion differs.

The reviewed downcall table is:

| Platform | Symbol | C/FFM shape |
| --- | --- | --- |
| Windows | `VirtualAlloc` | `void* (void*, size_t, int32, int32)` |
| Windows | `VirtualLock`, `VirtualUnlock` | `int32 (void*, size_t)` |
| Windows | `VirtualFree` | `int32 (void*, size_t, int32)` |
| Windows | `GetSystemInfo` | `void (SYSTEM_INFO*)`; asserted layout supplies page size |
| POSIX | `mmap` | `void* (void*, size_t, int, int, int, int64 off_t)` |
| POSIX | `mlock`, `munlock`, `munmap` | `int (void*, size_t)` |
| Linux | `madvise` | `int (void*, size_t, int)` |
| POSIX | `getrlimit`, `setrlimit` | `int (int, struct rlimit*)` |
| Linux | `prctl` | `int (int, unsigned long, unsigned long, unsigned long, unsigned long)` with `firstVariadicArg(1)` |

`PR_GET_DUMPABLE` is still linked as the variadic libc wrapper with four
width-correct zero arguments. Constants are grouped per ABI backend, cite the
authoritative Windows SDK, Linux UAPI/glibc, or Darwin SDK header next to their
definition, and are behavior-tested. No runtime header parser or native shim is
introduced.

On supported Windows x86-64, `SYSTEM_INFO` is asserted as a 48-byte,
8-byte-aligned layout: the processor union at offset 0, `dwPageSize` at 4,
the two address pointers at 8 and 16, pointer-width processor mask at 24,
32-bit processor count/type/allocation granularity at 32/36/40, and 16-bit
processor level/revision at 44/46. POSIX page size is read with `sysconf` using
the per-OS `_SC_PAGESIZE` constant and a canonical C `long` result; nonpositive
or non-power-of-two results fail closed.

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

Failure of `mmap`, `mlock`, or `MADV_DONTDUMP` is fatal. POSIX allocation
failure is only the pointer-width all-ones `MAP_FAILED` sentinel, which is
rejected before any `reinterpret`. A successful address-zero mapping is
separately rejected by Core's safety policy: it is immediately passed to
`munmap`, never reported as an `mmap`/errno failure, and produces the fixed
`ZERO_ADDRESS_REJECTED` operation detail. The exception otherwise identifies
only the operation and errno.

### macOS

The backend resolves documented libc symbols and uses:

1. `mmap` with the macOS value of `MAP_ANON`, plus `MAP_PRIVATE` and
   read/write protection.
2. `mlock` over the complete mapping.
3. Volatile byte writes for destruction.
4. `munlock`.
5. `munmap`.

Failure of `mmap` or `mlock` is fatal. `mmap` handles `MAP_FAILED` and a
successful address-zero result with the same distinct semantics as Linux.
macOS does not receive a Linux-style per-mapping dump-exclusion claim;
process-wide core-dump suppression belongs to the process hardening API.

### FFM safety rules

- Native function descriptors and constants live in platform-specific internal
  backends.
- Every fallible downcall uses `Linker.Option.captureCallState("errno")` on
  POSIX or `captureCallState("GetLastError")` on Windows and reads the captured
  value from that same invocation before another native call. Provider setup
  verifies the requested name exists in `captureStateLayout()` and fails closed
  otherwise. Unsigned Windows error values are exposed as nonnegative `long`s.
- Windows rejects null from `VirtualAlloc`. POSIX treats only `MAP_FAILED` as
  allocation failure; an address-zero success is unmapped and rejected under a
  separate fixed-code safety policy before reinterpretation.
- Page size and rounded allocation size use checked arithmetic.
- A zero-length logical secret still owns one protected page.
- No `MemorySegment` escapes the provider implementation.
- Each native secret has an `Arena.ofShared()` scope so current cross-thread
  callback and close behavior is preserved. Live segment access and explicit
  scope close occur while holding the owning `SecretMemory` monitor; the
  owner-free Cleaner state uses its private resource lock only after the owner
  becomes unreachable. No segment escapes.
- The implementation wipes the entire page-rounded mapping with a byte
  `VarHandle.setVolatile` for every byte followed by `VarHandle.fullFence()`.
  This is an ordering/compiler guarantee only; it does not promise cache, DRAM,
  hibernation-image, or privileged physical-reader erasure.

## Ownership state machine

A native secret advances through these internal states:

```text
ALLOCATED -> LOCKED -> DUMP_EXCLUDED (Linux) -> COPY_STARTED -> LIVE
LIVE -> WIPED -> UNLOCKED -> RELEASED
```

Windows and macOS omit `DUMP_EXCLUDED`. Input bytes are copied only after every
required protection has succeeded. The state advances to `COPY_STARTED` before
the first secret byte is written. Every exit at or after that state attempts a
full-mapping wipe before unlock/release, including a partially failed copy. If
construction fails, cleanup proceeds from the last state in reverse order. The
original fixed-message construction error wins; fixed-message cleanup errors
are suppressed only after every cleanup operation has been attempted.

`copyBytes` remains synchronized for the complete callback. It copies the
native secret into a temporary heap array, invokes the consumer, and wipes the
array in `finally`. Cross-thread `close` waits for an in-flight callback because
it acquires the same monitor. For monitor reentrancy, the owner tracks callback
depth: `close` called inside a callback marks the owner closed immediately but
defers native cleanup until the outermost callback exits. New or nested access
after that close request fails. Repeated close is a no-op after cleanup.

Cleanup attempts wiping, unlocking, and releasing even when an earlier cleanup
step fails. The first redacted cleanup exception is thrown after all steps have
been attempted; later redacted failures are suppressed. Logical closure is
separate from resource terminal state and never reopens access. After the one
cleanup pass the shared scope is invalidated even when `munmap`/`VirtualFree`
fails; a failed release can therefore leak the inaccessible mapping until
process exit and is not retried through a possibly stale pointer. A best-effort
`Cleaner` state object, which cannot retain the owner, performs the same
one-pass cleanup for abandoned objects. Deterministic close remains required;
quota exhaustion continues to fail closed.

The short-lived heap copy is an explicit residual boundary. Existing JCA,
Tink, and Bouncy Castle APIs consume arrays or provider-owned key objects, so
Core cannot claim that active cryptographic operations are heap-free. Existing
temporary-array wiping remains required.

## Process-hardening API

Process hardening is explicit. The first API has one intentionally named strict
operation rather than a speculative single-value policy enum:

```java
public final class ProcessHardening {
    public static @NonNull ProcessHardeningReport inspect();

    public static @NonNull ProcessHardeningReport applyStrict();
}

public enum HardeningStatus {
    ENFORCED,
    VERIFIED,
    NOT_ENFORCED,
    APPLICATION_REQUIRED,
    UNAVAILABLE,
    FAILED,
    NOT_ATTEMPTED
}
```

`HardeningControl` is the stable identifier enum. It contains the common,
Windows, Linux, and macOS controls named below. `HardeningResult` contains one
non-null control, one non-null status, and one fixed non-null redacted detail
code. `ProcessHardeningReport` contains a non-null detected-platform enum and
an immutable, defensively copied `List<@NonNull HardeningResult>` in control
enum order, exactly one entry for every control applicable to that platform.
It offers `@Nullable HardeningResult result(@NonNull HardeningControl control)`;
no nullness defaults are used. `equals`, `hashCode`, and `toString` are value
based and redaction-safe. Consumers must ignore future controls they do not
understand rather than assume an exhaustive set.

The initial stable control identifiers are `JAVA_25_OR_LATER`,
`MODULE_NATIVE_ACCESS`, `ILLEGAL_NATIVE_ACCESS_DENY`,
`JVM_ATTACH_DISABLED`, `HEAP_DUMP_ON_OOME_DISABLED`,
`NATIVE_LOCKED_MEMORY`, `JVM_DIAGNOSTIC_DUMP_ISOLATION`,
`OS_CRASH_DUMP_POLICY`, `OS_DEBUGGER_ISOLATION`,
`DEDICATED_PROCESS_IDENTITY`, `LINUX_DUMPABLE_ZERO`,
`POSIX_CORE_RLIMIT_ZERO`, `LINUX_YAMA_PTRACE_SCOPE`,
`LINUX_SERVICE_SANDBOX`, `MACOS_HARDENED_RUNTIME`, and
`MACOS_NOTARIZATION`, `MACOS_GET_TASK_ALLOW_ABSENT`,
`MACOS_LIBRARY_VALIDATION`, and `PRIVILEGED_ACCOUNT_SEPARATION`. Controls not
applicable to the detected platform are absent rather than assigned a
misleading status.

Status semantics are exact:

| Status | Meaning at report-return time |
| --- | --- |
| `VERIFIED` | The control was already effective and was read back by this call. |
| `ENFORCED` | This call changed the control and then read it back as effective. |
| `NOT_ENFORCED` | The control is supported and observable but is currently ineffective. |
| `APPLICATION_REQUIRED` | Core cannot safely enforce or authoritatively verify this deployment responsibility. |
| `UNAVAILABLE` | This runtime cannot inspect or apply a control that should be supported. |
| `FAILED` | An attempted process mutation or its read-back verification failed. |
| `NOT_ATTEMPTED` | A prior failure prevented this later mutation in the fixed order. |

Reports are snapshots, not durable attestations. In-process native code,
privileged actors, or later configuration can change controls after return.
`inspect()` never mutates and therefore never returns `ENFORCED`; an applicable
but currently disabled control is `NOT_ENFORCED`. `applyStrict()` returns
`ENFORCED` only for a change made and reread by that invocation, and `VERIFIED`
when the effective state already matched. Deployment controls remain
`APPLICATION_REQUIRED`; Core never converts self-attestation to `ENFORCED`.

`applyStrict()` is serialized across the process, monotonic, idempotent in
effect, and explicitly non-transactional. It first completes every
side-effect-free preflight: supported tuple/HotSpot, Java/native-access state,
effective JVM options, native-memory probe, native symbol/layout availability,
and current process-control reads. An unavailable or ineffective immutable
strict prerequisite (Java/HotSpot, native access, effective JVM options,
ABI/symbols, or native-memory protection) throws
`ProcessHardeningException` with a complete redacted report before mutation.
`NOT_ENFORCED` is expected for a mutable OS target and advances to mutation;
only an `UNAVAILABLE`/unreadable mutable target prevents mutation. It then
applies controls in fixed order: Linux dumpability, read-back, and finally the
irreversible POSIX hard/soft core limit and its read-back. macOS applies only
the final limit step. Repeated calls reread current state and never claim
rollback.

If a mutation fails after an earlier change, the exception carries a complete
redacted per-control report using `ENFORCED`, `FAILED`, and `NOT_ATTEMPTED` as
appropriate. The already-applied state remains in force; retry begins from the
observed state and attempts only missing controls. Raw causes are never attached.
Lowering the hard `RLIMIT_CORE` to zero is irreversible for an unprivileged
process and is documented as such.

### Common controls

- Verify Java 25 or later.
- Verify native access for the Keystead module.
- Report `--illegal-native-access=deny` as an application-required launcher
  control because Java exposes no authoritative effective-state query; argument
  text is not treated as attestation.
- On the supported HotSpot runtime, read the effective
  `DisableAttachMechanism` and `HeapDumpOnOutOfMemoryError` values through
  `HotSpotDiagnosticMXBean`; contradictory repeated launcher flags are resolved
  by effective state, not text. A different VM is unsupported and fails closed.
- Probe the native locked-memory backend.

Java 25, module native access, effective attach disabling, effective
heap-dump-on-OOME disabling, and the locked-memory probe are strict required
preconditions. The general ability of in-process code to request a diagnostic
heap dump remains outside the threat model and is reported narrowly as an
application isolation responsibility.

### Windows controls

Core applies no process ACL or broad `SetProcessMitigationPolicy` mutation.
Those policies can interfere with the JVM, JIT, service control, monitoring,
and crash handling, and cannot distinguish another process running under the
same account. The report marks dedicated service identity, restrictive process
permissions, crash-dump policy, and administrator separation as application
requirements.

### Linux controls

Core sets and verifies `prctl(PR_SET_DUMPABLE, 0)` and sets/verifies both soft
and hard `RLIMIT_CORE` as zero under the narrow control identifiers
`LINUX_DUMPABLE_ZERO` and `POSIX_CORE_RLIMIT_ZERO`. The report marks system Yama `ptrace_scope`,
dedicated UID, service sandboxing, and root separation as application
requirements because the library cannot safely set system-wide policy.

### macOS controls

Core sets and verifies both soft and hard `RLIMIT_CORE` as zero under
`POSIX_CORE_RLIMIT_ZERO`. The report
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
callback-versus-close atomicity. Fake operations verify every volatile byte
write across the rounded mapping, a final fence, and continued unlock/release
attempts after an injected wipe failure. An internal test hook checks that a
real mapping contains only zeroes immediately before release.

Boundary tests cover zero-length secrets, exact page size, first byte over a
page, checked rounding overflow, Windows null, POSIX `MAP_FAILED`, successful
POSIX address zero with mandatory unmap and fixed policy error, ABI
size/alignment assertions, symbol/captured-state failure, per-allocation quota
failure, duplicate hardening calls, and missing JVM flags. Lifecycle tests cover
cross-thread copy, cross-thread close, repeated close, close from callback,
nested copy, partial-copy failure, abandoned-owner cleanup, and release failure
without reopened access. Redaction tests traverse messages, `toString`, causes,
suppressed graphs, reports, and logging serialization for secret bytes,
addresses, user names, identifiers, command lines, library paths, and vault
paths.

Deterministic service/crypto tests inject `heap()` or fake native operations so
the page-per-secret default cannot make the general suite depend on host lock
quotas. A small serialized integration group is the only group that allocates
real locked pages. It records page size and current lock limit in test-only
diagnostics, never raises host limits, and includes a real convenience-default
test proving native selection and fail-closed behavior.

### Subprocess tests

Process-global controls and launcher flags are tested in child JVMs. Tests run
with and without native access, attach disabling, and heap-dump flags. Linux
children verify `PR_GET_DUMPABLE` and `getrlimit`; macOS children verify
`getrlimit`; Windows children verify real `VirtualLock` allocation and the
honest `APPLICATION_REQUIRED` process-isolation results.

The Gradle test configuration asserts named-module execution before granting
`--enable-native-access=top.focess.keystead.core`. Separate classpath fixtures
use `ALL-UNNAMED`. No-access children launch with
`--illegal-native-access=deny`; subprocess cases include contradictory repeated
HotSpot flags, argument-file launches, and environment-provided JVM options.
Process-global limits are applied only in expendable child JVMs, never the
Gradle daemon or reusable main test worker.

Linux/macOS mutation children deliberately start with nonzero applicable
dumpability/core-limit state, call `applyStrict()`, and prove the mutable targets
are applied, reread, and reported rather than rejected by immutable-prerequisite
preflight.

### Cross-platform integration

A GitHub Actions matrix runs pinned Temurin Java 25 on Windows x86-64, Linux
x86-64/AArch64, and macOS x86-64/AArch64. The test/integration JVM receives the
appropriate native-access grant; Spotless runs independently. All existing
Java-21 workflow definitions (`ci`, `build`, and CodeQL) are upgraded together
or consolidated so no stale job remains.

Linux inspects a live mapping's `/proc/self/smaps` `Locked:` value and
dump-exclusion `VmFlags` marker, then verifies the mapping disappears after
close. Windows/macOS assert the documented native calls and their read-back
where the OS exposes it, without claiming debugger resistance. Expected
authoritative facilities on a claimed runner must pass rather than silently
skip. Null/address-zero/`MAP_FAILED`, symbol/layout, wrong-flag, cleanup-order, and redaction
tests run on every platform/architecture tuple.

The local platform's complete suite must pass before commit. A platform backend
is not considered verified solely because fake-backend tests pass; all five
architecture matrix jobs are required evidence before the feature is declared
complete.

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
