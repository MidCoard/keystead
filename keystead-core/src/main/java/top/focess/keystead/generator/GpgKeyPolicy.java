package top.focess.keystead.generator;

import java.util.Arrays;
import java.util.Date;
import java.util.Objects;
import java.util.function.Consumer;
import org.jspecify.annotations.NonNull;

/**
 * Parameters for generating an OpenPGP key: identity, passphrase, creation time, and RSA key size
 * (at least 3072 bits). The constructor defensively copies the passphrase; the caller retains
 * ownership of the supplied array and must wipe it. Closing wipes the retained copy.
 */
public final class GpgKeyPolicy implements AutoCloseable {

    /** Default RSA key size. */
    public static final int DEFAULT_RSA_BITS = 3072;

    private final String identity;
    private final char[] passphrase;
    private final Date createdAt;
    private final int rsaBits;
    private boolean closed;

    /**
     * Creates a policy with the current time and default RSA key size.
     *
     * @param identity the OpenPGP identity
     * @param passphrase the passphrase; copied, and remains the caller's responsibility to wipe
     */
    public GpgKeyPolicy(@NonNull String identity, char @NonNull [] passphrase) {
        this(identity, passphrase, new Date(), DEFAULT_RSA_BITS);
    }

    /**
     * Creates a policy with the default RSA key size.
     *
     * @param identity the OpenPGP identity
     * @param passphrase the passphrase; copied, and remains the caller's responsibility to wipe
     * @param createdAt the key creation time
     */
    public GpgKeyPolicy(
            @NonNull String identity, char @NonNull [] passphrase, @NonNull Date createdAt) {
        this(identity, passphrase, createdAt, DEFAULT_RSA_BITS);
    }

    /**
     * Creates a policy with an explicit RSA key size.
     *
     * @param identity the OpenPGP identity
     * @param passphrase the passphrase; copied, and remains the caller's responsibility to wipe
     * @param createdAt the key creation time
     * @param rsaBits the RSA key size in bits; at least 3072
     */
    public GpgKeyPolicy(
            @NonNull String identity,
            char @NonNull [] passphrase,
            @NonNull Date createdAt,
            int rsaBits) {
        String validatedIdentity = requireText(identity, "identity");
        Objects.requireNonNull(passphrase, "passphrase");
        if (passphrase.length == 0) {
            throw new IllegalArgumentException("passphrase must not be blank");
        }
        Date validatedCreatedAt =
                new Date(Objects.requireNonNull(createdAt, "createdAt").getTime());
        if (rsaBits < 3072) {
            throw new IllegalArgumentException("rsaBits must be at least 3072");
        }
        this.identity = validatedIdentity;
        this.passphrase = Arrays.copyOf(passphrase, passphrase.length);
        this.createdAt = validatedCreatedAt;
        this.rsaBits = rsaBits;
    }

    /** Returns the OpenPGP identity.
     *
     * @return the OpenPGP identity */
    public @NonNull String identity() {
        requireOpen();
        return identity;
    }

    /** Returns the key creation time.
     *
     * @return the key creation time */
    public @NonNull Date createdAt() {
        requireOpen();
        return new Date(createdAt.getTime());
    }

    /** Returns the RSA key size in bits.
     *
     * @return the RSA key size */
    public int rsaBits() {
        requireOpen();
        return rsaBits;
    }

    /**
     * Exposes a copy of the passphrase to the consumer and wipes the copy afterwards.
     *
     * @param consumer the consumer of the passphrase copy
     */
    public void copyPassphrase(@NonNull Consumer<char[]> consumer) {
        Objects.requireNonNull(consumer, "consumer");
        requireOpen();
        char[] copy = Arrays.copyOf(passphrase, passphrase.length);
        try {
            consumer.accept(copy);
        } finally {
            Arrays.fill(copy, '\0');
        }
    }

    @Override
    public void close() {
        if (!closed) {
            Arrays.fill(passphrase, '\0');
            closed = true;
        }
    }

    private void requireOpen() {
        if (closed) {
            throw new IllegalStateException("GPG key policy has been closed");
        }
    }

    private static @NonNull String requireText(@NonNull String value, @NonNull String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value.trim();
    }
}
