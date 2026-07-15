# Keystead Core Native Memory and Process Hardening Implementation Plan

> Execute this plan test-first in `D:\IdeaProjects\.keystead-worktrees\core-security-hardening`. Preserve the unstaged `VaultServiceTest.java` diff with SHA-256 `4AF69A9917F64BE7C252783007F14E336EFAC48C6EF10D8710DC66B3046F4BA5` and never include it in a commit.

**Goal:** Make fail-closed locked native memory the Keystead Core default on the five approved 64-bit OS/architecture tuples and expose explicit strict process hardening without weakening zero-knowledge or redaction boundaries.

**Architecture:** Keep the public memory contracts in `top.focess.keystead.memory` and add process-wide APIs in exported `top.focess.keystead.security`. Internal FFM backends live below `top.focess.keystead.memory.internal`, share a reviewed ABI layer, and are injected behind a narrow operations interface for deterministic crash/failure tests. Real process mutations run only in child JVMs.

**Technology:** Java 25 FFM, Gradle 9.6.1 toolchains, JUnit 5, JSpecify, HotSpot diagnostic MXBean, Windows Kernel32, Linux/macOS libc.

## Task 1: Provision and prove the Java 25 named module

**Files:**

- Modify: `settings.gradle.kts`
- Modify: `keystead-core/build.gradle.kts`
- Create: `keystead-core/src/main/java/module-info.java`
- Create: `keystead-core/src/test/java/top/focess/keystead/module/ModuleContractTest.java`

1. Add a failing module contract test that checks the Core module name, exported public packages, native-access visibility, Java 25 runtime, and Tink automatic module name.
2. Run `./gradlew :keystead-core:test --tests '*ModuleContractTest' --no-daemon` and capture the expected failure on the current Java-21 build.
3. Add Foojay resolver 1.0.0, request Temurin/Adoptium Java 25, enable module-path inference, and add a complete module descriptor exporting all existing public packages plus `top.focess.keystead.security`.
4. Configure named-module tests with the scoped native-access grant and a separate classpath consumer fixture with `ALL-UNNAMED`.
5. Run the focused test and `:keystead-core:compileJava`; inspect `javaToolchains` output to confirm Temurin 25.
6. Commit build/module files and focused tests only.

## Task 2: Define immutable redacted public report contracts

**Files:**

- Create: `keystead-core/src/main/java/top/focess/keystead/memory/NativePlatform.java`
- Create: `keystead-core/src/main/java/top/focess/keystead/memory/NativeProtectionControl.java`
- Create: `keystead-core/src/main/java/top/focess/keystead/memory/NativeProtectionStatus.java`
- Create: `keystead-core/src/main/java/top/focess/keystead/memory/NativeProtectionResult.java`
- Create: `keystead-core/src/main/java/top/focess/keystead/memory/NativeMemoryProtectionReport.java`
- Create: `keystead-core/src/main/java/top/focess/keystead/memory/NativeMemoryOperation.java`
- Create: `keystead-core/src/main/java/top/focess/keystead/memory/NativeMemoryUnavailableException.java`
- Create: `keystead-core/src/test/java/top/focess/keystead/memory/NativeMemoryReportTest.java`

1. Write failing tests for stable enum order, defensive immutable copies, nullable lookup, value equality, unsigned Windows error conversion, and redaction-safe message/`toString`/cause/suppressed graphs.
2. Run the focused test and confirm compilation/test failure.
3. Implement the smallest explicitly annotated value objects and fixed detail/error vocabulary. Never attach raw causes.
4. Run the focused test and Spotless.
5. Commit the public memory report model and tests.

## Task 3: Build the checked ABI and injected native-operations boundary

**Files:**

- Create: `keystead-core/src/main/java/top/focess/keystead/memory/internal/NativeAbi.java`
- Create: `keystead-core/src/main/java/top/focess/keystead/memory/internal/NativeOperations.java`
- Create: `keystead-core/src/main/java/top/focess/keystead/memory/internal/NativeOperationResult.java`
- Create: `keystead-core/src/main/java/top/focess/keystead/memory/internal/PlatformNativeOperations.java`
- Create: `keystead-core/src/test/java/top/focess/keystead/memory/internal/NativeAbiTest.java`
- Create: `keystead-core/src/test/java/top/focess/keystead/memory/internal/FakeNativeOperations.java`

1. Write failing tests for five supported tuples, unsupported tuple failure, canonical layout size/alignment, checked page rounding, capture-state-name availability, Windows null, POSIX `MAP_FAILED`, and address-zero cleanup policy.
2. Run the focused tests and record the expected failures.
3. Implement side-effect-free platform detection, checked arithmetic, ABI assertions, and an injectable operation interface. Keep FFM segments and addresses internal.
4. Run the focused tests and Spotless.
5. Commit the ABI/operations boundary and tests.

## Task 4: Implement native ownership and crash-injected cleanup

**Files:**

- Create: `keystead-core/src/main/java/top/focess/keystead/memory/internal/NativeSecretMemory.java`
- Create: `keystead-core/src/main/java/top/focess/keystead/memory/NativeLockedSecretMemoryProvider.java`
- Modify: `keystead-core/src/main/java/top/focess/keystead/memory/SecretMemoryProvider.java`
- Create: `keystead-core/src/test/java/top/focess/keystead/memory/internal/NativeSecretMemoryTest.java`
- Modify: `keystead-core/src/test/java/top/focess/keystead/memory/SecretMemoryProviderTest.java`

1. Write failing fake-backend tests for every construction state and injected failure: allocation, lock, dump exclusion, partial copy, full-map volatile wipe, unlock, release, and suppressed redacted cleanup failures.
2. Add failing lifecycle tests for cross-thread copy/close, nested copy, close from callback, repeated close, abandoned-owner Cleaner, release failure, and quota exhaustion without access reopening.
3. Implement the `ALLOCATED -> LOCKED -> DUMP_EXCLUDED -> COPY_STARTED -> LIVE` state machine with a shared arena, callback-depth-aware close, one-pass cleanup, and owner-free Cleaner state.
4. Add `systemDefault()`, `nativeLocked()`, and explicit `heap()` factories; keep provider acquisition safely lazy and `SecretMemoryProvider` functional.
5. Run focused lifecycle tests repeatedly and run Spotless.
6. Commit native ownership/provider code and tests.

## Task 5: Implement Windows, Linux, and macOS FFM backends

**Files:**

- Create: `keystead-core/src/main/java/top/focess/keystead/memory/internal/FfmSupport.java`
- Create: `keystead-core/src/main/java/top/focess/keystead/memory/internal/WindowsNativeOperations.java`
- Create: `keystead-core/src/main/java/top/focess/keystead/memory/internal/PosixNativeOperations.java`
- Create: `keystead-core/src/main/java/top/focess/keystead/memory/internal/LinuxNativeOperations.java`
- Create: `keystead-core/src/main/java/top/focess/keystead/memory/internal/MacOsNativeOperations.java`
- Create: `keystead-core/src/main/java/top/focess/keystead/memory/NativeMemoryProtection.java`
- Create: `keystead-core/src/test/java/top/focess/keystead/memory/NativeMemoryProtectionIntegrationTest.java`

1. Write failing local integration tests for capability-report ordering and a serialized one-page protect/copy/wipe/unlock/release cycle.
2. Implement reviewed function descriptors/constants, per-call `captureCallState`, `MAP_FAILED` handling, address-zero unmap policy, full-map volatile wipe/fence, and transient inspection reporting.
3. Add platform-specific authoritative test hooks: Linux `smaps`; Windows documented return values; macOS documented return values. Never claim debugger resistance.
4. Run fake tests on every backend and the real local Windows integration test with native access.
5. Run Spotless and commit backend/integration files.

## Task 6: Make native protection the Core convenience default

**Files:**

- Modify: `keystead-core/src/main/java/top/focess/keystead/memory/SecretBuffer.java`
- Modify: `keystead-core/src/main/java/top/focess/keystead/crypto/VaultKey.java`
- Modify: `keystead-core/src/main/java/top/focess/keystead/crypto/DeviceKeyPair.java`
- Modify: `keystead-core/src/main/java/top/focess/keystead/crypto/DefaultCryptoService.java`
- Modify: `keystead-core/src/main/java/top/focess/keystead/generator/DefaultMfaSecretGenerator.java`
- Modify: `keystead-core/src/main/java/top/focess/keystead/generator/DefaultGpgKeyGenerator.java`
- Modify deterministic tests under `keystead-core/src/test/java/top/focess/keystead`

1. Add failing tests proving every convenience path chooses `systemDefault()` and fails closed when native protection is unavailable.
2. Change only convenience defaults; retain every explicit provider overload.
3. Inject `heap()` or fakes in deterministic service/crypto tests to avoid lock-quota flakiness while preserving a real default-path integration test.
4. Run the complete Core unit suite and Spotless.
5. Commit default migration and test adjustments, excluding the protected `VaultServiceTest.java` diff.

## Task 7: Define and implement strict process-hardening reports

**Files:**

- Create public classes/enums under `keystead-core/src/main/java/top/focess/keystead/security/`
- Create internal controls under `keystead-core/src/main/java/top/focess/keystead/security/internal/`
- Create tests under `keystead-core/src/test/java/top/focess/keystead/security/`

1. Write failing value/redaction tests for `HardeningControl`, `HardeningStatus`, `HardeningResult`, `ProcessHardeningReport`, and report-carrying `ProcessHardeningException`.
2. Write failing control tests for immutable prerequisites, mutable OS targets, deterministic order, snapshot status semantics, concurrency serialization, partial irreversible failure, and idempotent retry.
3. Implement effective HotSpot option reads through `HotSpotDiagnosticMXBean`, module native-access/native-probe checks, and fixed deployment responsibility results.
4. Implement Linux `prctl` plus POSIX `getrlimit`/`setrlimit` behind injected operations; keep Windows/macOS debugger policy honest.
5. Run focused tests and Spotless; commit report/control code.

## Task 8: Prove process-global behavior in expendable child JVMs

**Files:**

- Create: `keystead-core/src/test/java/top/focess/keystead/security/ProcessHardeningSubprocessTest.java`
- Create: `keystead-core/src/test/java/top/focess/keystead/security/HardeningProbeMain.java`
- Modify: `keystead-core/build.gradle.kts`

1. Add child launchers for named-module and classpath native-access grants, missing/deny cases, contradictory HotSpot flags, argument files, and environment JVM options.
2. Add Linux/macOS children starting with nonzero mutable controls; prove `applyStrict()` mutates, rereads, and reports them. Add partial-failure child scenarios without changing the main test worker.
3. Add Windows child evidence for native locked memory plus `APPLICATION_REQUIRED` OS debugger isolation.
4. Run the local Windows subprocess suite twice and confirm no process-global state leaks into Gradle.
5. Commit subprocess tests/configuration.

## Task 9: Update contributor documentation and five-tuple CI

**Files:**

- Modify: `README.md`
- Modify: `.github/workflows/ci.yml`
- Modify or consolidate: `.github/workflows/build.yml`
- Modify: `.github/workflows/codeql-analysis.yml`

1. Rewrite the Core technical sections for Java 25, module/classpath launcher flags, fail-closed default, explicit heap downgrade, lifecycle closure, per-platform enforcement, deployment responsibilities, and bounded in-memory guarantees.
2. Configure pinned Temurin 25 jobs for Windows x86-64, Linux x86-64/AArch64, and macOS x86-64/AArch64; keep Spotless independent and authoritative facilities non-skipping.
3. Upgrade/consolidate every Java-21 workflow so none remains stale.
4. Validate workflow syntax, run README link/path checks, Spotless, and `git diff --check`.
5. Commit documentation and CI only.

## Task 10: Complete local verification and independent review

1. Verify the protected test hash and staged scope before every commit.
2. Run `./gradlew :keystead-core:clean :keystead-core:test :keystead-core:spotlessCheck --no-daemon --rerun-tasks` with the required native-access test configuration.
3. Run module-path and classpath fixtures, real native integration tests, and all child-process hardening tests.
4. Inspect XML totals and permitted skips; run `git diff --check` and `git status --short`.
5. Request independent security/code review and fix every Critical/Important issue test-first.
6. Push only after explicit authorization, obtain all five CI results, and do not declare the active lifecycle goal complete until those results and remaining lifecycle coverage are real.
