package top.focess.keystead.security.internal;

import org.jspecify.annotations.NonNull;

/**
 * Soft and hard {@code RLIMIT_CORE} values.
 *
 * @param soft the soft limit in bytes
 * @param hard the hard limit in bytes
 */
public record CoreLimit(long soft, long hard) {

    /**
     * Returns the soft limit in bytes.
     *
     * @return the soft limit in bytes
     */
    @Override
    public long soft() {
        return soft;
    }

    /**
     * Returns the hard limit in bytes.
     *
     * @return the hard limit in bytes
     */
    @Override
    public long hard() {
        return hard;
    }

    @Override
    public @NonNull String toString() {
        return "CoreLimit[soft=" + soft + ", hard=" + hard + "]";
    }
}
