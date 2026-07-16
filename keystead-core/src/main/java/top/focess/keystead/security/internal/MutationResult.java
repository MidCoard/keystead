package top.focess.keystead.security.internal;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/** Result of one process mutation. */
public record MutationResult(boolean successful, @Nullable Long osErrorCode) {

    public MutationResult {
        if (osErrorCode != null && osErrorCode < 0L) {
            throw new IllegalArgumentException("OS error code must not be negative");
        }
    }

    @Override
    public boolean successful() {
        return successful;
    }

    @Override
    public @Nullable Long osErrorCode() {
        return osErrorCode;
    }

    @Override
    public @NonNull String toString() {
        return "MutationResult[successful=" + successful + ", osErrorCode=" + osErrorCode + "]";
    }

    public static @NonNull MutationResult success() {
        return new MutationResult(true, null);
    }

    public static @NonNull MutationResult failure(long osErrorCode) {
        return new MutationResult(false, osErrorCode);
    }
}
