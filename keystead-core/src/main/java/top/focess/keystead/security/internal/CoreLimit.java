package top.focess.keystead.security.internal;

import org.jspecify.annotations.NonNull;

/** Soft and hard {@code RLIMIT_CORE} values. */
public record CoreLimit(long soft, long hard) {

    @Override
    public long soft() {
        return soft;
    }

    @Override
    public long hard() {
        return hard;
    }

    @Override
    public @NonNull String toString() {
        return "CoreLimit[soft=" + soft + ", hard=" + hard + "]";
    }
}
