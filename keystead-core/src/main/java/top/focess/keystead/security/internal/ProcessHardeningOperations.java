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

    /**
     * Returns the detected native platform.
     *
     * @return the detected native platform
     */
    @NonNull NativePlatform platform();

    /**
     * Returns the Java runtime major version.
     *
     * @return the Java runtime major version
     */
    int javaMajorVersion();

    /**
     * Returns whether the Keystead Core module has native access enabled.
     *
     * @return whether the Keystead Core module has native access enabled
     */
    boolean nativeAccessEnabled();

    /**
     * Reads an effective HotSpot option value.
     *
     * @param name the HotSpot option name
     * @return the effective value, or {@code null} if the option or MXBean is unavailable
     */
    @Nullable String hotSpotOption(@NonNull String name);

    /**
     * Runs the transient native-memory capability probe.
     *
     * @return the native-memory protection report for the current platform
     */
    @NonNull NativeMemoryProtectionReport nativeMemoryProbe();

    /**
     * Reads the Linux dumpable flag.
     *
     * @return the Linux {@code PR_GET_DUMPABLE} value (0, 1, or 2), or {@code null} if it cannot be
     *     read
     */
    @Nullable Integer readDumpable();

    /**
     * Reads the POSIX core-file resource limit.
     *
     * @return the {@code RLIMIT_CORE} soft and hard values, or {@code null} if they cannot be read
     */
    @Nullable CoreLimit readCoreLimit();

    /**
     * Sets the process dumpable flag to zero via Linux {@code prctl(PR_SET_DUMPABLE, 0)}.
     *
     * @return the mutation result, including the OS error code on failure
     */
    @NonNull MutationResult setDumpableZero();

    /**
     * Sets both {@code RLIMIT_CORE} values to zero via POSIX {@code setrlimit(RLIMIT_CORE, 0, 0)}.
     *
     * @return the mutation result, including the OS error code on failure
     */
    @NonNull MutationResult setCoreLimitZero();
}
