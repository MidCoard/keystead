package top.focess.keystead.security.internal;

import java.util.ArrayList;
import java.util.List;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.memory.NativeMemoryProtectionReport;
import top.focess.keystead.memory.NativePlatform;
import top.focess.keystead.memory.NativeProtectionControl;
import top.focess.keystead.memory.NativeProtectionStatus;
import top.focess.keystead.security.HardeningControl;
import top.focess.keystead.security.HardeningResult;
import top.focess.keystead.security.HardeningStatus;
import top.focess.keystead.security.ProcessHardeningException;
import top.focess.keystead.security.ProcessHardeningReport;

/**
 * Builds {@link ProcessHardeningReport}s from injectable {@link ProcessHardeningOperations}.
 *
 * <p>{@code inspect()} never mutates and therefore never reports {@link HardeningStatus#ENFORCED}.
 * {@code applyStrict()} is serialized, monotonic, idempotent, and non-transactional: it completes
 * every immutable-prerequisite preflight before mutation, then applies Linux dumpability and the
 * irreversible POSIX core limit (macOS applies only the core limit) with read-back. A failed
 * mutation or unavailable mutable target throws {@link ProcessHardeningException} with a complete
 * redacted report; already-applied state remains in force and retry begins from the observed state.
 */
public final class ProcessHardeningInspector {

    private static final @NonNull Object APPLY_LOCK = new Object();

    private ProcessHardeningInspector() {}

    /**
     * Builds a non-mutating snapshot of the applicable controls.
     *
     * @param operations the operations used to read process and platform state
     * @return a redacted snapshot report; never reports {@link HardeningStatus#ENFORCED}
     */
    public static @NonNull ProcessHardeningReport inspect(
            @NonNull ProcessHardeningOperations operations) {
        NativePlatform platform = operations.platform();
        List<HardeningResult> results = new ArrayList<>();

        results.add(javaVersionResult(operations));
        results.add(nativeAccessResult(operations));
        results.add(applicationRequired(HardeningControl.ILLEGAL_NATIVE_ACCESS_DENY));
        results.add(
                hotSpotBooleanResult(
                        operations,
                        HardeningControl.JVM_ATTACH_DISABLED,
                        "DisableAttachMechanism",
                        true));
        results.add(
                hotSpotBooleanResult(
                        operations,
                        HardeningControl.HEAP_DUMP_ON_OOME_DISABLED,
                        "HeapDumpOnOutOfMemoryError",
                        false));
        results.add(nativeLockedMemoryResult(operations));
        results.add(applicationRequired(HardeningControl.JVM_DIAGNOSTIC_DUMP_ISOLATION));
        results.add(applicationRequired(HardeningControl.OS_CRASH_DUMP_POLICY));
        results.add(applicationRequired(HardeningControl.OS_DEBUGGER_ISOLATION));
        results.add(applicationRequired(HardeningControl.DEDICATED_PROCESS_IDENTITY));
        if (isLinux(platform)) {
            results.add(dumpableSnapshot(operations));
            results.add(coreLimitSnapshot(operations));
            results.add(applicationRequired(HardeningControl.LINUX_YAMA_PTRACE_SCOPE));
            results.add(applicationRequired(HardeningControl.LINUX_SERVICE_SANDBOX));
        }
        if (isMacOs(platform)) {
            results.add(coreLimitSnapshot(operations));
            results.add(applicationRequired(HardeningControl.MACOS_HARDENED_RUNTIME));
            results.add(applicationRequired(HardeningControl.MACOS_NOTARIZATION));
            results.add(applicationRequired(HardeningControl.MACOS_GET_TASK_ALLOW_ABSENT));
            results.add(applicationRequired(HardeningControl.MACOS_LIBRARY_VALIDATION));
        }
        results.add(applicationRequired(HardeningControl.PRIVILEGED_ACCOUNT_SEPARATION));

        return new ProcessHardeningReport(platform, results);
    }

    /**
     * Applies strict hardening: preflights immutable prerequisites, then mutates and verifies the
     * platform's mutable controls.
     *
     * @param operations the operations used to read and mutate process state
     * @return a redacted report of the resulting control states
     * @throws ProcessHardeningException if a prerequisite is unmet or a mutation fails
     */
    public static @NonNull ProcessHardeningReport applyStrict(
            @NonNull ProcessHardeningOperations operations) {
        synchronized (APPLY_LOCK) {
            NativePlatform platform = operations.platform();
            ProcessHardeningReport snapshot = inspect(operations);
            if (findUnmetImmutablePrerequisite(snapshot) != null) {
                throw new ProcessHardeningException(snapshot);
            }

            List<HardeningResult> results = new ArrayList<>(snapshot.results());
            boolean mutationBlocked = false;
            if (isLinux(platform)) {
                mutationBlocked = applyDumpable(results, operations);
                if (mutationBlocked) {
                    setNotAttempted(results, HardeningControl.POSIX_CORE_RLIMIT_ZERO);
                } else {
                    mutationBlocked = applyCoreLimit(results, operations);
                }
            } else if (isMacOs(platform)) {
                mutationBlocked = applyCoreLimit(results, operations);
            }

            ProcessHardeningReport report = new ProcessHardeningReport(platform, results);
            if (mutationBlocked) {
                throw new ProcessHardeningException(report);
            }
            return report;
        }
    }

    private static boolean applyDumpable(
            @NonNull List<@NonNull HardeningResult> results,
            @NonNull ProcessHardeningOperations operations) {
        int index = indexOf(results, HardeningControl.LINUX_DUMPABLE_ZERO);
        if (index < 0) {
            return false;
        }
        Integer current = operations.readDumpable();
        if (current == null) {
            results.set(index, unavailable(HardeningControl.LINUX_DUMPABLE_ZERO));
            return true;
        }
        if (current == 0) {
            results.set(index, verified(HardeningControl.LINUX_DUMPABLE_ZERO));
            return false;
        }
        MutationResult mutation = operations.setDumpableZero();
        if (!mutation.successful()) {
            HardeningResult failure =
                    failed(HardeningControl.LINUX_DUMPABLE_ZERO, mutation.osErrorCode());
            results.set(index, failure);
            return true;
        }
        Integer readBack = operations.readDumpable();
        if (readBack == null || readBack != 0) {
            results.set(index, failed(HardeningControl.LINUX_DUMPABLE_ZERO, null));
            return true;
        }
        results.set(index, enforced(HardeningControl.LINUX_DUMPABLE_ZERO));
        return false;
    }

    private static boolean applyCoreLimit(
            @NonNull List<@NonNull HardeningResult> results,
            @NonNull ProcessHardeningOperations operations) {
        int index = indexOf(results, HardeningControl.POSIX_CORE_RLIMIT_ZERO);
        if (index < 0) {
            return false;
        }
        CoreLimit current = operations.readCoreLimit();
        if (current == null) {
            results.set(index, unavailable(HardeningControl.POSIX_CORE_RLIMIT_ZERO));
            return true;
        }
        if (current.soft() == 0L && current.hard() == 0L) {
            results.set(index, verified(HardeningControl.POSIX_CORE_RLIMIT_ZERO));
            return false;
        }
        MutationResult mutation = operations.setCoreLimitZero();
        if (!mutation.successful()) {
            HardeningResult failure =
                    failed(HardeningControl.POSIX_CORE_RLIMIT_ZERO, mutation.osErrorCode());
            results.set(index, failure);
            return true;
        }
        CoreLimit readBack = operations.readCoreLimit();
        if (readBack == null || readBack.soft() != 0L || readBack.hard() != 0L) {
            results.set(index, failed(HardeningControl.POSIX_CORE_RLIMIT_ZERO, null));
            return true;
        }
        results.set(index, enforced(HardeningControl.POSIX_CORE_RLIMIT_ZERO));
        return false;
    }

    private static int indexOf(
            @NonNull List<@NonNull HardeningResult> results, @NonNull HardeningControl control) {
        for (int i = 0; i < results.size(); i++) {
            if (results.get(i).control() == control) {
                return i;
            }
        }
        return -1;
    }

    private static void setNotAttempted(
            @NonNull List<@NonNull HardeningResult> results, @NonNull HardeningControl control) {
        int index = indexOf(results, control);
        if (index >= 0) {
            results.set(
                    index,
                    new HardeningResult(
                            control,
                            HardeningStatus.NOT_ATTEMPTED,
                            HardeningResult.DETAIL_NOT_ATTEMPTED,
                            null));
        }
    }

    @Nullable private static HardeningResult findUnmetImmutablePrerequisite(
            @NonNull ProcessHardeningReport report) {
        for (HardeningControl prerequisite :
                new HardeningControl[] {
                    HardeningControl.JAVA_25_OR_LATER,
                    HardeningControl.MODULE_NATIVE_ACCESS,
                    HardeningControl.JVM_ATTACH_DISABLED,
                    HardeningControl.HEAP_DUMP_ON_OOME_DISABLED,
                    HardeningControl.NATIVE_LOCKED_MEMORY
                }) {
            HardeningResult result = report.result(prerequisite);
            if (result == null || result.status() != HardeningStatus.VERIFIED) {
                return result;
            }
        }
        return null;
    }

    private static @NonNull HardeningResult dumpableSnapshot(
            @NonNull ProcessHardeningOperations operations) {
        Integer value = operations.readDumpable();
        if (value == null) {
            return unavailable(HardeningControl.LINUX_DUMPABLE_ZERO);
        }
        boolean enforced = value == 0;
        return new HardeningResult(
                HardeningControl.LINUX_DUMPABLE_ZERO,
                enforced ? HardeningStatus.VERIFIED : HardeningStatus.NOT_ENFORCED,
                enforced ? HardeningResult.DETAIL_VERIFIED : HardeningResult.DETAIL_NOT_ENFORCED,
                null);
    }

    private static @NonNull HardeningResult coreLimitSnapshot(
            @NonNull ProcessHardeningOperations operations) {
        CoreLimit limit = operations.readCoreLimit();
        if (limit == null) {
            return unavailable(HardeningControl.POSIX_CORE_RLIMIT_ZERO);
        }
        boolean enforced = limit.soft() == 0L && limit.hard() == 0L;
        return new HardeningResult(
                HardeningControl.POSIX_CORE_RLIMIT_ZERO,
                enforced ? HardeningStatus.VERIFIED : HardeningStatus.NOT_ENFORCED,
                enforced ? HardeningResult.DETAIL_VERIFIED : HardeningResult.DETAIL_NOT_ENFORCED,
                null);
    }

    private static @NonNull HardeningResult javaVersionResult(
            @NonNull ProcessHardeningOperations operations) {
        boolean java25OrLater = operations.javaMajorVersion() >= 25;
        return new HardeningResult(
                HardeningControl.JAVA_25_OR_LATER,
                java25OrLater ? HardeningStatus.VERIFIED : HardeningStatus.UNAVAILABLE,
                java25OrLater
                        ? HardeningResult.DETAIL_VERIFIED
                        : HardeningResult.DETAIL_UNAVAILABLE,
                null);
    }

    private static @NonNull HardeningResult nativeAccessResult(
            @NonNull ProcessHardeningOperations operations) {
        boolean enabled = operations.nativeAccessEnabled();
        return new HardeningResult(
                HardeningControl.MODULE_NATIVE_ACCESS,
                enabled ? HardeningStatus.VERIFIED : HardeningStatus.UNAVAILABLE,
                enabled ? HardeningResult.DETAIL_VERIFIED : HardeningResult.DETAIL_UNAVAILABLE,
                null);
    }

    private static @NonNull HardeningResult hotSpotBooleanResult(
            @NonNull ProcessHardeningOperations operations,
            @NonNull HardeningControl control,
            @NonNull String optionName,
            boolean desiredValue) {
        String value = operations.hotSpotOption(optionName);
        if (value == null) {
            return unavailable(control);
        }
        boolean effective = Boolean.parseBoolean(value);
        return new HardeningResult(
                control,
                effective == desiredValue ? HardeningStatus.VERIFIED : HardeningStatus.NOT_ENFORCED,
                effective == desiredValue
                        ? HardeningResult.DETAIL_VERIFIED
                        : HardeningResult.DETAIL_NOT_ENFORCED,
                null);
    }

    private static @NonNull HardeningResult nativeLockedMemoryResult(
            @NonNull ProcessHardeningOperations operations) {
        NativeMemoryProtectionReport probe = operations.nativeMemoryProbe();
        NativeProtectionStatus allocation =
                probe.result(NativeProtectionControl.ALLOCATION).status();
        HardeningStatus status =
                switch (allocation) {
                    case VERIFIED -> HardeningStatus.VERIFIED;
                    case FAILED -> HardeningStatus.FAILED;
                    default -> HardeningStatus.UNAVAILABLE;
                };
        return new HardeningResult(
                HardeningControl.NATIVE_LOCKED_MEMORY,
                status,
                status == HardeningStatus.VERIFIED
                        ? HardeningResult.DETAIL_VERIFIED
                        : status == HardeningStatus.FAILED
                                ? HardeningResult.DETAIL_FAILED
                                : HardeningResult.DETAIL_UNAVAILABLE,
                null);
    }

    private static @NonNull HardeningResult applicationRequired(@NonNull HardeningControl control) {
        return new HardeningResult(
                control,
                HardeningStatus.APPLICATION_REQUIRED,
                HardeningResult.DETAIL_APPLICATION_REQUIRED,
                null);
    }

    private static @NonNull HardeningResult verified(@NonNull HardeningControl control) {
        return new HardeningResult(
                control, HardeningStatus.VERIFIED, HardeningResult.DETAIL_VERIFIED, null);
    }

    private static @NonNull HardeningResult enforced(@NonNull HardeningControl control) {
        return new HardeningResult(
                control, HardeningStatus.ENFORCED, HardeningResult.DETAIL_ENFORCED, null);
    }

    private static @NonNull HardeningResult unavailable(@NonNull HardeningControl control) {
        return new HardeningResult(
                control, HardeningStatus.UNAVAILABLE, HardeningResult.DETAIL_UNAVAILABLE, null);
    }

    private static @NonNull HardeningResult failed(
            @NonNull HardeningControl control, @Nullable Long osErrorCode) {
        return new HardeningResult(
                control, HardeningStatus.FAILED, HardeningResult.DETAIL_FAILED, osErrorCode);
    }

    private static boolean isLinux(@NonNull NativePlatform platform) {
        return platform == NativePlatform.LINUX_X86_64 || platform == NativePlatform.LINUX_AARCH64;
    }

    private static boolean isMacOs(@NonNull NativePlatform platform) {
        return platform == NativePlatform.MACOS_X86_64 || platform == NativePlatform.MACOS_AARCH64;
    }
}
