package top.focess.keystead.memory;

import java.util.Objects;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/** Immutable, redaction-safe result for one native-memory protection control. */
public record NativeProtectionResult(
        @NonNull NativeProtectionControl control,
        @NonNull NativeProtectionStatus status,
        @NonNull String detail,
        @Nullable Long osErrorCode) {

    public static final @NonNull String DETAIL_PLATFORM_SUPPORTED = "PLATFORM_SUPPORTED";
    public static final @NonNull String DETAIL_PLATFORM_UNSUPPORTED = "PLATFORM_UNSUPPORTED";
    public static final @NonNull String DETAIL_NATIVE_ACCESS_ENABLED = "NATIVE_ACCESS_ENABLED";
    public static final @NonNull String DETAIL_NATIVE_ACCESS_UNAVAILABLE =
            "NATIVE_ACCESS_UNAVAILABLE";
    public static final @NonNull String DETAIL_ABI_LAYOUTS_VERIFIED = "ABI_LAYOUTS_VERIFIED";
    public static final @NonNull String DETAIL_ABI_LAYOUTS_UNAVAILABLE = "ABI_LAYOUTS_UNAVAILABLE";
    public static final @NonNull String DETAIL_SYMBOLS_RESOLVED = "SYMBOLS_RESOLVED";
    public static final @NonNull String DETAIL_SYMBOLS_UNAVAILABLE = "SYMBOLS_UNAVAILABLE";
    public static final @NonNull String DETAIL_OPERATION_VERIFIED = "OPERATION_VERIFIED";
    public static final @NonNull String DETAIL_OPERATION_FAILED = "OPERATION_FAILED";
    public static final @NonNull String DETAIL_QUOTA_UNAVAILABLE = "QUOTA_UNAVAILABLE";
    public static final @NonNull String DETAIL_NOT_APPLICABLE = "NOT_APPLICABLE";
    public static final @NonNull String DETAIL_NOT_ATTEMPTED = "NOT_ATTEMPTED";
    public static final @NonNull String DETAIL_ZERO_ADDRESS_REJECTED = "ZERO_ADDRESS_REJECTED";

    private static final @NonNull Set<@NonNull String> ALLOWED_DETAILS =
            Set.of(
                    DETAIL_PLATFORM_SUPPORTED,
                    DETAIL_PLATFORM_UNSUPPORTED,
                    DETAIL_NATIVE_ACCESS_ENABLED,
                    DETAIL_NATIVE_ACCESS_UNAVAILABLE,
                    DETAIL_ABI_LAYOUTS_VERIFIED,
                    DETAIL_ABI_LAYOUTS_UNAVAILABLE,
                    DETAIL_SYMBOLS_RESOLVED,
                    DETAIL_SYMBOLS_UNAVAILABLE,
                    DETAIL_OPERATION_VERIFIED,
                    DETAIL_OPERATION_FAILED,
                    DETAIL_QUOTA_UNAVAILABLE,
                    DETAIL_NOT_APPLICABLE,
                    DETAIL_NOT_ATTEMPTED,
                    DETAIL_ZERO_ADDRESS_REJECTED);

    public NativeProtectionResult {
        Objects.requireNonNull(control, "control");
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(detail, "detail");
        if (!ALLOWED_DETAILS.contains(detail)) {
            throw new IllegalArgumentException("Unsupported native protection detail code");
        }
        if (osErrorCode != null && osErrorCode < 0L) {
            throw new IllegalArgumentException("OS error code must not be negative");
        }
    }

    public static @NonNull NativeProtectionResult withWindowsError(
            @NonNull NativeProtectionControl control,
            @NonNull NativeProtectionStatus status,
            @NonNull String detail,
            int windowsErrorCode) {
        return new NativeProtectionResult(
                control, status, detail, Integer.toUnsignedLong(windowsErrorCode));
    }

    @Override
    public @NonNull NativeProtectionControl control() {
        return control;
    }

    @Override
    public @NonNull NativeProtectionStatus status() {
        return status;
    }

    @Override
    public @NonNull String detail() {
        return detail;
    }

    @Override
    public @Nullable Long osErrorCode() {
        return osErrorCode;
    }

    @Override
    public @NonNull String toString() {
        return "NativeProtectionResult[control="
                + control
                + ", status="
                + status
                + ", detail="
                + detail
                + ", osErrorCode="
                + osErrorCode
                + "]";
    }
}
