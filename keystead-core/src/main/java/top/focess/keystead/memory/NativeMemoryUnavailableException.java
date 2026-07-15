package top.focess.keystead.memory;

import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/** Redacted unchecked failure raised when required native-memory protection is unavailable. */
public final class NativeMemoryUnavailableException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final @NonNull NativePlatform platform;
    private final @NonNull NativeMemoryOperation operation;
    private final @Nullable Long osErrorCode;

    public NativeMemoryUnavailableException(
            @NonNull NativePlatform platform, @NonNull NativeMemoryOperation operation) {
        this(platform, operation, null);
    }

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

    public static @NonNull NativeMemoryUnavailableException fromWindowsError(
            @NonNull NativePlatform platform,
            @NonNull NativeMemoryOperation operation,
            int windowsErrorCode) {
        return new NativeMemoryUnavailableException(
                platform, operation, Integer.toUnsignedLong(windowsErrorCode));
    }

    public @NonNull NativePlatform platform() {
        return platform;
    }

    public @NonNull NativeMemoryOperation operation() {
        return operation;
    }

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
