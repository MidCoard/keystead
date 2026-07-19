package top.focess.keystead.memory;

import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/** Redacted unchecked failure raised when required native-memory protection is unavailable. */
public final class NativeMemoryUnavailableException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /** The platform on which the operation was attempted. */
    private final @NonNull NativePlatform platform;

    /** The native-memory operation that was unavailable. */
    private final @NonNull NativeMemoryOperation operation;

    /** The OS error code, or {@code null} when no OS error was involved. */
    private final @Nullable Long osErrorCode;

    /**
     * Creates the exception without an OS error code.
     *
     * @param platform the platform on which the operation was attempted
     * @param operation the native-memory operation that was unavailable
     */
    public NativeMemoryUnavailableException(
            @NonNull NativePlatform platform, @NonNull NativeMemoryOperation operation) {
        this(platform, operation, null);
    }

    /**
     * Creates the exception with an OS error code.
     *
     * @param platform the platform on which the operation was attempted
     * @param operation the native-memory operation that was unavailable
     * @param osErrorCode the OS error code; must not be negative
     */
    public NativeMemoryUnavailableException(
            @NonNull NativePlatform platform,
            @NonNull NativeMemoryOperation operation,
            long osErrorCode) {
        this(platform, operation, Long.valueOf(osErrorCode));
    }

    private NativeMemoryUnavailableException(
            @NonNull NativePlatform platform,
            @NonNull NativeMemoryOperation operation,
            @Nullable Long osErrorCode) {
        super(message(platform, operation, osErrorCode), null);
        this.platform = Objects.requireNonNull(platform, "platform");
        this.operation = Objects.requireNonNull(operation, "operation");
        if (osErrorCode != null && osErrorCode < 0L) {
            throw new IllegalArgumentException("OS error code must not be negative");
        }
        this.osErrorCode = osErrorCode;
    }

    /**
     * Creates the exception from a Windows error code, widened to its unsigned value.
     *
     * @param platform the platform on which the operation was attempted
     * @param operation the native-memory operation that was unavailable
     * @param windowsErrorCode the Windows {@code GetLastError} value
     * @return the exception with the unsigned error code
     */
    public static @NonNull NativeMemoryUnavailableException fromWindowsError(
            @NonNull NativePlatform platform,
            @NonNull NativeMemoryOperation operation,
            int windowsErrorCode) {
        return new NativeMemoryUnavailableException(
                platform, operation, Integer.toUnsignedLong(windowsErrorCode));
    }

    /**
     * Returns the platform on which the operation was attempted.
     *
     * @return the platform on which the operation was attempted
     */
    public @NonNull NativePlatform platform() {
        return platform;
    }

    /**
     * Returns the native-memory operation that was unavailable.
     *
     * @return the native-memory operation that was unavailable
     */
    public @NonNull NativeMemoryOperation operation() {
        return operation;
    }

    /**
     * Returns the OS error code.
     *
     * @return the OS error code, or {@code null} when no OS error was involved
     */
    public @Nullable Long osErrorCode() {
        return osErrorCode;
    }

    @Override
    public @NonNull String toString() {
        return "NativeMemoryUnavailableException[platform="
                + platform
                + ", operation="
                + operation
                + ", osErrorCode="
                + osErrorCode
                + "]";
    }

    private static @NonNull String message(
            @NonNull NativePlatform platform,
            @NonNull NativeMemoryOperation operation,
            @Nullable Long osErrorCode) {
        Objects.requireNonNull(platform, "platform");
        Objects.requireNonNull(operation, "operation");
        return "Native memory protection unavailable [platform="
                + platform
                + ", operation="
                + operation
                + ", osErrorCode="
                + osErrorCode
                + "]";
    }
}
