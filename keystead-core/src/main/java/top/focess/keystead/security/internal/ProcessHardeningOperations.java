package top.focess.keystead.security.internal;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.memory.NativeMemoryProtectionReport;
import top.focess.keystead.memory.NativePlatform;

/**
 * Injectable process-hardening operations used by {@link ProcessHardeningInspector}. The real
 * implementation reads effective HotSpot options and probes native memory; deterministic fakes
 * drive the control tests without touching the host process.
 */
public interface ProcessHardeningOperations {

    @NonNull NativePlatform platform();

    int javaMajorVersion();

    boolean nativeAccessEnabled();

    /** Effective HotSpot option value, or {@code null} if the option or MXBean is unavailable. */
    @Nullable String hotSpotOption(@NonNull String name);

    @NonNull NativeMemoryProtectionReport nativeMemoryProbe();
}
