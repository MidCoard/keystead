package top.focess.keystead.security;

import java.util.Objects;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/** Immutable, redaction-safe result for one process-hardening control. */
public record HardeningResult(
        @NonNull HardeningControl control,
        @NonNull HardeningStatus status,
        @NonNull String detail,
        @Nullable Long osErrorCode) {

    public static final @NonNull String DETAIL_VERIFIED = "VERIFIED";
    public static final @NonNull String DETAIL_ENFORCED = "ENFORCED";
    public static final @NonNull String DETAIL_NOT_ENFORCED = "NOT_ENFORCED";
    public static final @NonNull String DETAIL_APPLICATION_REQUIRED = "APPLICATION_REQUIRED";
    public static final @NonNull String DETAIL_UNAVAILABLE = "UNAVAILABLE";
    public static final @NonNull String DETAIL_FAILED = "FAILED";
    public static final @NonNull String DETAIL_NOT_ATTEMPTED = "NOT_ATTEMPTED";
    public static final @NonNull String DETAIL_PREREQUISITE_UNAVAILABLE =
            "PREREQUISITE_UNAVAILABLE";
    public static final @NonNull String DETAIL_IMMUTABLE_PREREQUISITE_UNMET =
            "IMMUTABLE_PREREQUISITE_UNMET";

    private static final @NonNull Set<@NonNull String> ALLOWED_DETAILS =
            Set.of(
                    DETAIL_VERIFIED,
                    DETAIL_ENFORCED,
                    DETAIL_NOT_ENFORCED,
                    DETAIL_APPLICATION_REQUIRED,
                    DETAIL_UNAVAILABLE,
                    DETAIL_FAILED,
                    DETAIL_NOT_ATTEMPTED,
                    DETAIL_PREREQUISITE_UNAVAILABLE,
                    DETAIL_IMMUTABLE_PREREQUISITE_UNMET);

    public HardeningResult {
        Objects.requireNonNull(control, "control");
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(detail, "detail");
        if (!ALLOWED_DETAILS.contains(detail)) {
            throw new IllegalArgumentException("Unsupported hardening detail code");
        }
        if (osErrorCode != null && osErrorCode < 0L) {
            throw new IllegalArgumentException("OS error code must not be negative");
        }
    }

    public static @NonNull HardeningResult withWindowsError(
            @NonNull HardeningControl control,
            @NonNull HardeningStatus status,
            @NonNull String detail,
            int windowsErrorCode) {
        return new HardeningResult(
                control, status, detail, Integer.toUnsignedLong(windowsErrorCode));
    }

    @Override
    public @NonNull HardeningControl control() {
        return control;
    }

    @Override
    public @NonNull HardeningStatus status() {
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
        return "HardeningResult[control="
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
