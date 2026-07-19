package top.focess.keystead.memory.internal;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.ArrayList;
import java.util.List;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.memory.NativeMemoryProtectionReport;
import top.focess.keystead.memory.NativeMemoryUnavailableException;
import top.focess.keystead.memory.NativePlatform;
import top.focess.keystead.memory.NativeProtectionControl;
import top.focess.keystead.memory.NativeProtectionResult;
import top.focess.keystead.memory.NativeProtectionStatus;

/**
 * Transient native-memory capability probe backing {@code NativeMemoryProtection.inspect()}.
 *
 * <p>Performs a one-page allocate/lock/dump-exclude(Linux)/wipe/unlock/release probe without
 * retaining the page and records one {@link NativeProtectionResult} per control in enum order. A
 * missing prerequisite marks that control {@link NativeProtectionStatus#UNAVAILABLE} and every
 * dependent control {@link NativeProtectionStatus#NOT_ATTEMPTED}; an OS operation failure is
 * {@link NativeProtectionStatus#FAILED}; Windows/macOS dump exclusion is {@link
 * NativeProtectionStatus#NOT_APPLICABLE}. Capability failure is report data and never throws.
 */
public final class NativeMemoryProtectionInspector {

    private NativeMemoryProtectionInspector() {}

    /**
     * Runs the transient one-page probe and builds the platform's protection report.
     *
     * @return a redacted report with one entry per {@link NativeProtectionControl} in enum order
     */
    public static @NonNull NativeMemoryProtectionReport inspect() {
        NativePlatform platform =
                NativeAbi.detectPlatform(
                        System.getProperty("os.name"),
                        System.getProperty("os.arch"),
                        System.getProperty("sun.arch.data.model"),
                        System.getProperty("java.vm.name"));
        List<NativeProtectionResult> results = new ArrayList<>();

        if (platform == NativePlatform.UNSUPPORTED) {
            results.add(
                    result(
                            NativeProtectionControl.PLATFORM,
                            NativeProtectionStatus.UNAVAILABLE,
                            NativeProtectionResult.DETAIL_PLATFORM_UNSUPPORTED,
                            null));
            fillRemaining(results, NativeProtectionControl.NATIVE_ACCESS);
            return new NativeMemoryProtectionReport(platform, results);
        }
        results.add(
                result(
                        NativeProtectionControl.PLATFORM,
                        NativeProtectionStatus.VERIFIED,
                        NativeProtectionResult.DETAIL_PLATFORM_SUPPORTED,
                        null));

        if (!NativeMemoryProtectionInspector.class.getModule().isNativeAccessEnabled()) {
            results.add(
                    result(
                            NativeProtectionControl.NATIVE_ACCESS,
                            NativeProtectionStatus.UNAVAILABLE,
                            NativeProtectionResult.DETAIL_NATIVE_ACCESS_UNAVAILABLE,
                            null));
            fillRemaining(results, NativeProtectionControl.ABI_LAYOUTS);
            return new NativeMemoryProtectionReport(platform, results);
        }
        results.add(
                result(
                        NativeProtectionControl.NATIVE_ACCESS,
                        NativeProtectionStatus.VERIFIED,
                        NativeProtectionResult.DETAIL_NATIVE_ACCESS_ENABLED,
                        null));

        try {
            FfmSupport.requireAbi(platform);
        } catch (NativeMemoryUnavailableException e) {
            results.add(
                    result(
                            NativeProtectionControl.ABI_LAYOUTS,
                            NativeProtectionStatus.UNAVAILABLE,
                            NativeProtectionResult.DETAIL_ABI_LAYOUTS_UNAVAILABLE,
                            null));
            fillRemaining(results, NativeProtectionControl.SYMBOLS);
            return new NativeMemoryProtectionReport(platform, results);
        }
        results.add(
                result(
                        NativeProtectionControl.ABI_LAYOUTS,
                        NativeProtectionStatus.VERIFIED,
                        NativeProtectionResult.DETAIL_ABI_LAYOUTS_VERIFIED,
                        null));

        NativeOperations operations;
        try {
            operations = NativeBackends.create(platform);
        } catch (NativeMemoryUnavailableException e) {
            results.add(
                    result(
                            NativeProtectionControl.SYMBOLS,
                            NativeProtectionStatus.UNAVAILABLE,
                            NativeProtectionResult.DETAIL_SYMBOLS_UNAVAILABLE,
                            null));
            fillRemaining(results, NativeProtectionControl.ALLOCATION);
            return new NativeMemoryProtectionReport(platform, results);
        }
        results.add(
                result(
                        NativeProtectionControl.SYMBOLS,
                        NativeProtectionStatus.VERIFIED,
                        NativeProtectionResult.DETAIL_SYMBOLS_RESOLVED,
                        null));

        probe(operations, platform, results);
        return new NativeMemoryProtectionReport(platform, results);
    }

    private static void probe(
            @NonNull NativeOperations operations,
            @NonNull NativePlatform platform,
            @NonNull List<NativeProtectionResult> results) {
        long byteSize = operations.pageSize();
        Arena arena = Arena.ofShared();
        long address = 0L;
        boolean releaseAttempted = false;
        try {
            NativeOperationResult allocation = operations.allocate(byteSize);
            if (!allocation.successful()) {
                results.add(toFailed(NativeProtectionControl.ALLOCATION, allocation));
                fillRemaining(results, NativeProtectionControl.PAGE_LOCK);
                return;
            }
            results.add(verified(NativeProtectionControl.ALLOCATION));
            address = allocation.value();
            MemorySegment segment =
                    MemorySegment.ofAddress(address).reinterpret(byteSize, arena, null);

            NativeOperationResult lock = operations.lock(address, byteSize);
            if (!lock.successful()) {
                results.add(toFailed(NativeProtectionControl.PAGE_LOCK, lock));
                fillRemaining(results, NativeProtectionControl.DUMP_EXCLUSION);
                return;
            }
            results.add(verified(NativeProtectionControl.PAGE_LOCK));

            if (isLinux(platform)) {
                NativeOperationResult dumpExclusion = operations.dumpExclude(address, byteSize);
                if (!dumpExclusion.successful()) {
                    results.add(toFailed(NativeProtectionControl.DUMP_EXCLUSION, dumpExclusion));
                    fillRemaining(results, NativeProtectionControl.WIPE);
                    return;
                }
                results.add(verified(NativeProtectionControl.DUMP_EXCLUSION));
            } else {
                results.add(
                        result(
                                NativeProtectionControl.DUMP_EXCLUSION,
                                NativeProtectionStatus.NOT_APPLICABLE,
                                NativeProtectionResult.DETAIL_NOT_APPLICABLE,
                                null));
            }

            NativeOperationResult wipe = operations.wipe(segment, byteSize);
            if (!wipe.successful()) {
                results.add(toFailed(NativeProtectionControl.WIPE, wipe));
                fillRemaining(results, NativeProtectionControl.PAGE_UNLOCK);
                return;
            }
            results.add(verified(NativeProtectionControl.WIPE));

            NativeOperationResult unlock = operations.unlock(address, byteSize);
            if (!unlock.successful()) {
                results.add(toFailed(NativeProtectionControl.PAGE_UNLOCK, unlock));
                fillRemaining(results, NativeProtectionControl.RELEASE);
                return;
            }
            results.add(verified(NativeProtectionControl.PAGE_UNLOCK));

            releaseAttempted = true;
            NativeOperationResult release = operations.release(address, byteSize);
            if (!release.successful()) {
                results.add(toFailed(NativeProtectionControl.RELEASE, release));
                return;
            }
            results.add(verified(NativeProtectionControl.RELEASE));
        } finally {
            if (address != 0L && !releaseAttempted) {
                try {
                    operations.release(address, byteSize);
                } catch (RuntimeException ignored) {
                    // best-effort cleanup of a partially probed mapping
                }
            }
            arena.close();
        }
    }

    private static boolean isLinux(@NonNull NativePlatform platform) {
        return platform == NativePlatform.LINUX_X86_64 || platform == NativePlatform.LINUX_AARCH64;
    }

    private static void fillRemaining(
            @NonNull List<NativeProtectionResult> results, @NonNull NativeProtectionControl from) {
        NativeProtectionControl[] controls = NativeProtectionControl.values();
        for (int index = from.ordinal(); index < controls.length; index++) {
            results.add(
                    result(
                            controls[index],
                            NativeProtectionStatus.NOT_ATTEMPTED,
                            NativeProtectionResult.DETAIL_NOT_ATTEMPTED,
                            null));
        }
    }

    private static @NonNull NativeProtectionResult toFailed(
            @NonNull NativeProtectionControl control, @NonNull NativeOperationResult result) {
        if (NativeOperationResult.DETAIL_ZERO_ADDRESS_REJECTED.equals(result.detail())) {
            return result(
                    control,
                    NativeProtectionStatus.FAILED,
                    NativeProtectionResult.DETAIL_ZERO_ADDRESS_REJECTED,
                    null);
        }
        return result(
                control,
                NativeProtectionStatus.FAILED,
                NativeProtectionResult.DETAIL_OPERATION_FAILED,
                result.osErrorCode());
    }

    private static @NonNull NativeProtectionResult verified(
            @NonNull NativeProtectionControl control) {
        return result(
                control,
                NativeProtectionStatus.VERIFIED,
                NativeProtectionResult.DETAIL_OPERATION_VERIFIED,
                null);
    }

    private static @NonNull NativeProtectionResult result(
            @NonNull NativeProtectionControl control,
            @NonNull NativeProtectionStatus status,
            @NonNull String detail,
            @Nullable Long osErrorCode) {
        return new NativeProtectionResult(control, status, detail, osErrorCode);
    }
}
