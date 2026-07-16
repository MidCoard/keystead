package top.focess.keystead.security.internal;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.memory.NativeMemoryProtectionReport;
import top.focess.keystead.memory.NativePlatform;

/**
 * Injectable process-hardening operations used by {@link ProcessHardeningInspector}. The real
 * implementation reads effective HotSpot options, probes native memory, and (on Linux/macOS) reads
 * and mutates process dumpability and core limits; deterministic fakes drive the control tests
 * without touching the host process.
 */
public interface ProcessHardeningOperations {

    @NonNull NativePlatform platform();

    int javaMajorVersion();

    boolean nativeAccessEnabled();

    /** Effective HotSpot option value, or {@code null} if the option or MXBean is unavailable. */
    @Nullable String hotSpotOption(@NonNull String name);

    @NonNull NativeMemoryProtectionReport nativeMemoryProbe();

    /** Linux {@code PR_GET_DUMPABLE} value (0, 1, or 2), or {@code null} if it cannot be read. */
    @Nullable Integer readDumpable();

    /** POSIX {@code RLIMIT_CORE} soft and hard values, or {@code null} if they cannot be read. */
    @Nullable CoreLimit readCoreLimit();

    /** Linux {@code prctl(PR_SET_DUMPABLE, 0)}. */
    @NonNull MutationResult setDumpableZero();

    /** POSIX {@code setrlimit(RLIMIT_CORE, 0, 0)}. */
    @NonNull MutationResult setCoreLimitZero();
}
