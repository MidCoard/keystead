package top.focess.keystead.recovery;

import java.util.Arrays;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

/** Offline authority for one recovery enrollment generation. */
public final class RecoveryKit implements AutoCloseable {

    public static final int FORMAT_VERSION = 1;
    public static final int SECRET_BYTES = 32;

    private final int formatVersion;
    private final String enrollmentId;
    private final long generation;
    private final byte[] recoverySecret;
    private boolean closed;

    public RecoveryKit(
            int formatVersion,
            @NonNull String enrollmentId,
            long generation,
            byte @NonNull [] recoverySecret) {
        if (formatVersion != FORMAT_VERSION) {
            throw new IllegalArgumentException("Recovery kit format is unsupported");
        }
        this.enrollmentId = requireIdentifier(enrollmentId);
        if (generation <= 0) {
            throw new IllegalArgumentException("Recovery generation must be positive");
        }
        Objects.requireNonNull(recoverySecret, "recoverySecret");
        if (recoverySecret.length != SECRET_BYTES) {
            throw new IllegalArgumentException("Recovery secret must be 32 bytes");
        }
        this.formatVersion = formatVersion;
        this.generation = generation;
        this.recoverySecret = Arrays.copyOf(recoverySecret, recoverySecret.length);
    }

    public int formatVersion() {
        return formatVersion;
    }

    public @NonNull String enrollmentId() {
        return enrollmentId;
    }

    public long generation() {
        return generation;
    }

    public synchronized byte @NonNull [] recoverySecret() {
        requireOpen();
        return Arrays.copyOf(recoverySecret, recoverySecret.length);
    }

    public synchronized boolean isClosed() {
        return closed;
    }

    @Override
    public synchronized void close() {
        if (!closed) {
            Arrays.fill(recoverySecret, (byte) 0);
            closed = true;
        }
    }

    @Override
    public @NonNull String toString() {
        return "RecoveryKit(<redacted>)";
    }

    static @NonNull String requireIdentifier(@NonNull String value) {
        Objects.requireNonNull(value, "enrollmentId");
        if (value.isBlank()
                || value.length() > 128
                || value.chars().anyMatch(character -> Character.isISOControl(character))) {
            throw new IllegalArgumentException("Recovery enrollment id is invalid");
        }
        return value;
    }

    private void requireOpen() {
        if (closed) {
            throw new IllegalStateException("Recovery kit is closed");
        }
    }
}
