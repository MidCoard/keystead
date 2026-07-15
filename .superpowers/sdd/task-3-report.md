# Task 3 Implementer Report

## Result

Implemented the checked ABI and injected allocation/release boundary in commit
`a30702fb7cbaf6b466e2642e78564ebc84cd7086` (`Add checked native ABI boundary`). The implementation
is package-private, does not perform native downcalls, does not export FFM segments or addresses,
and keeps platform detection independent of native initialization.

## Toolchain and baseline

The host default was Temurin 21. Gradle's Java 25 auto-provisioning attempted the pinned Temurin
release but its GitHub HEAD request failed. Before any Task 3 production edit, the retained ZIP
`C:\Users\Administrator\Downloads\OpenJDK25U-jdk_x64_windows_hotspot_25.0.3_9.zip` was verified at
SHA-256 `709312CD0420296D9B9DE917FE6E28A5B979E875EE5AB91783FB79BCD5857235` and extracted under the
ignored `.gradle/task3-temurin-25` directory. With that Java 25 installation selected:

```powershell
.\gradlew.bat :keystead-core:test --console=plain
```

Output: `BUILD SUCCESSFUL` (3 tasks up-to-date). The worktree was the linked
`security/core-hardening` worktree at approved base
`dcd2510b4c33369a379d14b276274f01a43da703`.

## RED evidence

### Tuple detection and page rounding

After creating only the first wished-for tests:

```powershell
.\gradlew.bat :keystead-core:test --tests top.focess.keystead.memory.internal.NativeAbiTest --console=plain
```

Output: `BUILD FAILED`, exit 1, with 17 expected `cannot find symbol: NativeAbi` compilation errors.
No Task 3 production file existed.

### Canonical layouts and capture-state names

After the first cycle was green, tests were added for canonical Windows/POSIX layouts,
`SYSTEM_INFO`, `struct rlimit`, fail-closed mismatches, and capture-state-name availability. The
same focused command produced `BUILD FAILED`, exit 1, with 16 expected missing-method errors for
`requireCanonicalLayouts`, `windowsSystemInfoLayout`, `posixRlimitLayout`,
`captureStateName`, and `requireCaptureStateName`.

### Allocation sentinel and zero-address policy

After the layout cycle was green, tests and the fake subclass were added for Windows null, POSIX
`MAP_FAILED`, a valid high-bit POSIX address, and successful address zero. The focused command
produced `BUILD FAILED`, exit 1, with 18 expected missing-symbol errors for
`NativeOperations`, `NativeOperationResult`, and `PlatformNativeOperations`.

## GREEN evidence

Each cycle used the same focused command. The final focused run compiled and executed all 12
`NativeAbiTest` tests and reported:

```text
BUILD SUCCESSFUL in 4s
3 actionable tasks: 2 executed, 1 up-to-date
```

The tests prove:

- exactly five supported OS/architecture/data-model/VM tuples and fail-closed unsupported tuples;
- zero-length one-page ownership, exact-page behavior, first-byte-over-page behavior, invalid page
  rejection, and checked rounding overflow;
- canonical C `int`, `long`, `size_t`, `void*`, `int64_t` size/alignment/carrier checks;
- the asserted 48-byte/8-byte-aligned Windows `SYSTEM_INFO` offsets and the
  16-byte/8-byte-aligned POSIX `struct rlimit`;
- required `GetLastError`/`errno` capture-state layout members and fail-closed missing names;
- unsigned Windows error conversion, Windows null failure, POSIX all-ones-only `MAP_FAILED`, valid
  high-bit POSIX addresses, and stale-errno ignorance after success; and
- mandatory release attempt for successful POSIX address zero followed by fixed
  `ZERO_ADDRESS_REJECTED` with no mmap/errno attribution, even if release itself fails.

Formatting and fresh full verification:

```powershell
.\gradlew.bat :keystead-core:spotlessCheck --console=plain
.\gradlew.bat :keystead-core:check --rerun-tasks --console=plain
```

Output: both commands reported `BUILD SUCCESSFUL`; the full check executed 7/7 tasks, including
named-module tests, classpath compatibility tests, and Spotless. The output contained only the
pre-existing `DefaultCryptoService` deprecation notes and protobuf `Unsafe` warning.

## Files and commits

Implementation commit `a30702fb7cbaf6b466e2642e78564ebc84cd7086` changed exactly:

- `keystead-core/build.gradle.kts` (opens the new internal test package to JUnit only);
- `keystead-core/src/main/java/top/focess/keystead/memory/internal/NativeAbi.java`;
- `keystead-core/src/main/java/top/focess/keystead/memory/internal/NativeOperations.java`;
- `keystead-core/src/main/java/top/focess/keystead/memory/internal/NativeOperationResult.java`;
- `keystead-core/src/main/java/top/focess/keystead/memory/internal/PlatformNativeOperations.java`;
- `keystead-core/src/test/java/top/focess/keystead/memory/internal/NativeAbiTest.java`; and
- `keystead-core/src/test/java/top/focess/keystead/memory/internal/FakeNativeOperations.java`.

Implementation total: 7 files, 698 insertions. This report is committed separately as Task 3
evidence.

## Self-review

- All new production types are package-private and all reference-bearing production signatures use
  explicit JSpecify annotations; no package annotation default was added.
- Tuple detection takes explicit strings and performs no FFM initialization or native call.
- ABI failures use fixed, non-sensitive messages and discard raw layout-selection exceptions.
- The internal result's `toString()` deliberately omits its raw value so an address cannot be
  serialized accidentally.
- POSIX classification compares the raw return value only with pointer-width all-ones. It accepts
  other negative Java `long` bit patterns as possible high-bit addresses.
- Zero-address cleanup calls release before returning the fixed policy result and never reports the
  allocation's stale errno as a native failure.
- Task 5 downcalls, symbol resolution, reinterpretation, and real page operations were not added.

## Repository hygiene and concerns

The protected user-owned
`keystead-core/src/test/java/top/focess/keystead/service/VaultServiceTest.java` was never staged or
committed. Its final SHA-256 remains
`4AF69A9917F64BE7C252783007F14E336EFAC48C6EF10D8710DC66B3046F4BA5`, and its pre-existing
unstaged numstat remains `6/2`.

No Task 3 correctness concern remains. Environment note: Java 25 auto-provisioning was unavailable
during this run, so verification used the retained checksum-pinned Temurin 25 ZIP from the approved
instructions.
