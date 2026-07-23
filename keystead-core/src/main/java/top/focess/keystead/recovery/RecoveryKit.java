package top.focess.keystead.recovery;

import java.util.Arrays;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.Wipe;

/**
 * Offline authority for one recovery enrollment generation. The recovery secret is defensively
 * copied on construction and on access, and is wiped when the kit is closed.
 */
public final class RecoveryKit implements AutoCloseable {

    /** The recovery kit format version supported by this class. */
    public static final int FORMAT_VERSION = 1;

    /** The required length, in bytes, of the recovery secret. */
    public static final int SECRET_BYTES = 32;

    private final int formatVersion;
    private final String enrollmentId;
    private final long generation;
    private final byte[] recoverySecret;
    private boolean closed;

    /**
     * Creates a recovery kit for the given enrollment generation.
     *
     * @param formatVersion the kit format version; must equal {@link #FORMAT_VERSION}
     * @param enrollmentId the recovery enrollment identifier
     * @param generation the enrollment generation; must be positive
     * @param recoverySecret the 32-byte recovery secret; defensively copied
     */
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

    /** Returns the kit format version.
     *
     * @return the kit format version */
    public int formatVersion() {
        return formatVersion;
    }

    /** Returns the recovery enrollment identifier.
     *
     * @return the recovery enrollment identifier */
    public @NonNull String enrollmentId() {
        return enrollmentId;
    }

    /** Returns the enrollment generation.
     *
     * @return the enrollment generation */
    public long generation() {
        return generation;
    }

    /** Returns a defensive copy of the recovery secret.
     *
     * @return a defensive copy of the recovery secret */
    public synchronized byte @NonNull [] recoverySecret() {
        requireOpen();
        return Arrays.copyOf(recoverySecret, recoverySecret.length);
    }

    /** Returns whether this kit has been closed and its secret wiped.
     *
     * @return {@code true} if this kit has been closed */
    public synchronized boolean isClosed() {
        return closed;
    }

    @Override
    public synchronized void close() {
        if (!closed) {
            Wipe.wipe(recoverySecret);
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
