package top.focess.keystead.security;

import java.util.Objects;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Immutable, redaction-safe result for one process-hardening control.
 *
 * @param control the hardening control this result describes
 * @param status the control's status at report-return time
 * @param detail a fixed redacted detail code; one of the {@code DETAIL_*} constants
 * @param osErrorCode the OS error code for a failed operation, or {@code null}
 */
public record HardeningResult(
        @NonNull HardeningControl control,
        @NonNull HardeningStatus status,
        @NonNull String detail,
        @Nullable Long osErrorCode) {

    /** Detail code: the control was verified to already hold. */
    public static final @NonNull String DETAIL_VERIFIED = "VERIFIED";

    /** Detail code: the control was actively enforced by the library. */
    public static final @NonNull String DETAIL_ENFORCED = "ENFORCED";

    /** Detail code: the control is not enforced. */
    public static final @NonNull String DETAIL_NOT_ENFORCED = "NOT_ENFORCED";

    /** Detail code: enforcement is an application deployment responsibility. */
    public static final @NonNull String DETAIL_APPLICATION_REQUIRED = "APPLICATION_REQUIRED";

    /** Detail code: a prerequisite for the control is unavailable. */
    public static final @NonNull String DETAIL_UNAVAILABLE = "UNAVAILABLE";

    /** Detail code: an OS operation for the control failed. */
    public static final @NonNull String DETAIL_FAILED = "FAILED";

    /** Detail code: the control was not attempted because a prerequisite failed. */
    public static final @NonNull String DETAIL_NOT_ATTEMPTED = "NOT_ATTEMPTED";

    /** Detail code: a prerequisite control is unavailable. */
    public static final @NonNull String DETAIL_PREREQUISITE_UNAVAILABLE =
            "PREREQUISITE_UNAVAILABLE";

    /** Detail code: an immutable prerequisite (launcher or deployment) is unmet. */
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

    /** Validates the components and restricts {@code detail} to the fixed detail codes. */
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

    /**
     * Creates a result carrying a Windows error code, widened to its unsigned value.
     *
     * @param control the hardening control this result describes
     * @param status the control's status at report-return time
     * @param detail a fixed redacted detail code; one of the {@code DETAIL_*} constants
     * @param windowsErrorCode the Windows {@code GetLastError} value
     * @return the hardening result with the unsigned error code
     */
    public static @NonNull HardeningResult withWindowsError(
            @NonNull HardeningControl control,
            @NonNull HardeningStatus status,
            @NonNull String detail,
            int windowsErrorCode) {
        return new HardeningResult(
                control, status, detail, Integer.toUnsignedLong(windowsErrorCode));
    }

    /**
     * Returns the hardening control this result describes.
     *
     * @return the hardening control this result describes
     */
    @Override
    public @NonNull HardeningControl control() {
        return control;
    }

    /**
     * Returns the control's status at report-return time.
     *
     * @return the control's status at report-return time
     */
    @Override
    public @NonNull HardeningStatus status() {
        return status;
    }

    /**
     * Returns the fixed redacted detail code.
     *
     * @return the fixed redacted detail code
     */
    @Override
    public @NonNull String detail() {
        return detail;
    }

    /**
     * Returns the OS error code for a failed operation.
     *
     * @return the OS error code, or {@code null} when no OS error was involved
     */
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
