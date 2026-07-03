package top.focess.keystead.generator;

import java.util.Arrays;
import java.util.Date;
import java.util.Objects;
import java.util.function.Consumer;
import org.jspecify.annotations.NonNull;

public final class GpgKeyPolicy implements AutoCloseable {

    public static final int DEFAULT_RSA_BITS = 3072;

    private final String identity;
    private final char[] passphrase;
    private final Date createdAt;
    private final int rsaBits;
    private boolean closed;

    public GpgKeyPolicy(@NonNull String identity, char @NonNull [] passphrase) {
        this(identity, passphrase, new Date(), DEFAULT_RSA_BITS);
    }

    public GpgKeyPolicy(
            @NonNull String identity, char @NonNull [] passphrase, @NonNull Date createdAt) {
        this(identity, passphrase, createdAt, DEFAULT_RSA_BITS);
    }

    public GpgKeyPolicy(
            @NonNull String identity,
            char @NonNull [] passphrase,
            @NonNull Date createdAt,
            int rsaBits) {
        this.identity = requireText(identity, "identity");
        Objects.requireNonNull(passphrase, "passphrase");
        if (passphrase.length == 0) {
            throw new IllegalArgumentException("passphrase must not be blank");
        }
        this.passphrase = Arrays.copyOf(passphrase, passphrase.length);
        Arrays.fill(passphrase, '\0');
        this.createdAt = new Date(Objects.requireNonNull(createdAt, "createdAt").getTime());
        if (rsaBits < 3072) {
            throw new IllegalArgumentException("rsaBits must be at least 3072");
        }
        this.rsaBits = rsaBits;
    }

    public @NonNull String identity() {
        requireOpen();
        return identity;
    }

    public @NonNull Date createdAt() {
        requireOpen();
        return new Date(createdAt.getTime());
    }

    public int rsaBits() {
        requireOpen();
        return rsaBits;
    }

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
