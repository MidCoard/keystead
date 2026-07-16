package top.focess.keystead.security.internal;

import java.util.ArrayList;
import java.util.List;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.NativeMemoryProtectionReport;
import top.focess.keystead.memory.NativePlatform;
import top.focess.keystead.memory.NativeProtectionControl;
import top.focess.keystead.memory.NativeProtectionStatus;
import top.focess.keystead.security.HardeningControl;
import top.focess.keystead.security.HardeningResult;
import top.focess.keystead.security.HardeningStatus;
import top.focess.keystead.security.ProcessHardeningReport;

/**
 * Builds a {@link ProcessHardeningReport} from injectable {@link ProcessHardeningOperations}.
 *
 * <p>{@code inspect()} never mutates and therefore never reports {@link HardeningStatus#ENFORCED}.
 * The Core-enforceable Linux/macOS controls (dumpable zero, core rlimit zero) require native
 * read/mutate operations and are added with {@code applyStrict()} in the following task; until then
 * they are absent from the report rather than reported with a misleading status.
 */
public final class ProcessHardeningInspector {

    private ProcessHardeningInspector() {}

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
            results.add(applicationRequired(HardeningControl.LINUX_YAMA_PTRACE_SCOPE));
            results.add(applicationRequired(HardeningControl.LINUX_SERVICE_SANDBOX));
        }
        if (isMacOs(platform)) {
            results.add(applicationRequired(HardeningControl.MACOS_HARDENED_RUNTIME));
            results.add(applicationRequired(HardeningControl.MACOS_NOTARIZATION));
            results.add(applicationRequired(HardeningControl.MACOS_GET_TASK_ALLOW_ABSENT));
            results.add(applicationRequired(HardeningControl.MACOS_LIBRARY_VALIDATION));
        }
        results.add(applicationRequired(HardeningControl.PRIVILEGED_ACCOUNT_SEPARATION));

        return new ProcessHardeningReport(platform, results);
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
            return new HardeningResult(
                    control, HardeningStatus.UNAVAILABLE, HardeningResult.DETAIL_UNAVAILABLE, null);
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

    private static boolean isLinux(@NonNull NativePlatform platform) {
        return platform == NativePlatform.LINUX_X86_64 || platform == NativePlatform.LINUX_AARCH64;
    }

    private static boolean isMacOs(@NonNull NativePlatform platform) {
        return platform == NativePlatform.MACOS_X86_64 || platform == NativePlatform.MACOS_AARCH64;
    }
}
