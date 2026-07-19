package top.focess.keystead.memory;

import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.internal.NativeMemoryProtectionInspector;

/**
 * Transient native-memory capability inspection for the current platform.
 *
 * <p>{@link #inspect()} performs a one-page allocate/lock/dump-exclude(Linux)/wipe/unlock/release
 * probe without retaining the page and returns a redacted {@link NativeMemoryProtectionReport} with
 * one entry per {@link NativeProtectionControl} in enum order. A missing prerequisite is reported
 * as {@link NativeProtectionStatus#UNAVAILABLE} with dependent controls {@link
 * NativeProtectionStatus#NOT_ATTEMPTED}; an OS operation failure is {@link
 * NativeProtectionStatus#FAILED}; Windows/macOS dump exclusion is {@link
 * NativeProtectionStatus#NOT_APPLICABLE}. Capability failure is report data and never throws.
 */
public final class NativeMemoryProtection {

    private NativeMemoryProtection() {}

    /**
     * Probes native-memory protection capabilities for the current platform.
     *
     * @return a redacted report with one entry per {@link NativeProtectionControl} in enum order;
     *     capability failures are report data and never throw
     */
    public static @NonNull NativeMemoryProtectionReport inspect() {
        return NativeMemoryProtectionInspector.inspect();
    }
}
