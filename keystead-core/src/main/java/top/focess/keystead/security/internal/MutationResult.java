package top.focess.keystead.security.internal;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Result of one process mutation.
 *
 * @param successful whether the mutation succeeded
 * @param osErrorCode the OS error code on failure, or {@code null}
 */
public record MutationResult(boolean successful, @Nullable Long osErrorCode) {

    /** Validates that the OS error code is not negative. */
    public MutationResult {
        if (osErrorCode != null && osErrorCode < 0L) {
            throw new IllegalArgumentException("OS error code must not be negative");
        }
    }

    /**
     * Returns whether the mutation succeeded.
     *
     * @return whether the mutation succeeded
     */
    @Override
    public boolean successful() {
        return successful;
    }

    /**
     * Returns the OS error code on failure.
     *
     * @return the OS error code, or {@code null} when the mutation succeeded
     */
    @Override
    public @Nullable Long osErrorCode() {
        return osErrorCode;
    }

    @Override
    public @NonNull String toString() {
        return "MutationResult[successful=" + successful + ", osErrorCode=" + osErrorCode + "]";
    }

    /**
     * Creates a successful mutation result.
     *
     * @return a successful mutation result
     */
    public static @NonNull MutationResult success() {
        return new MutationResult(true, null);
    }

    /**
     * Creates a failed mutation result carrying an OS error code.
     *
     * @param osErrorCode the OS error code; must not be negative
     * @return a failed mutation result
     */
    public static @NonNull MutationResult failure(long osErrorCode) {
        return new MutationResult(false, osErrorCode);
    }
}
