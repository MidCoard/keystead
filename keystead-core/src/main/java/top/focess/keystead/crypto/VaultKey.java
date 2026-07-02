package top.focess.keystead.crypto;

import java.util.Arrays;
import java.util.Objects;
import java.util.function.Consumer;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.KeyId;

public final class VaultKey implements AutoCloseable {

    private final KeyId keyId;
    private final byte[] keyBytes;
    private boolean closed;

    VaultKey(@NonNull KeyId keyId, byte @NonNull [] keyBytes) {
        this.keyId = Objects.requireNonNull(keyId, "keyId");
        this.keyBytes =
                Arrays.copyOf(Objects.requireNonNull(keyBytes, "keyBytes"), keyBytes.length);
    }

    public @NonNull KeyId keyId() {
        return keyId;
    }

    public boolean isClosed() {
        return closed;
    }

    public void copyBytes(@NonNull Consumer<byte[]> consumer) {
        Objects.requireNonNull(consumer, "consumer");
        requireOpen();
        byte[] copy = Arrays.copyOf(keyBytes, keyBytes.length);
        try {
            consumer.accept(copy);
        } finally {
            Arrays.fill(copy, (byte) 0);
        }
    }

    @Override
    public void close() {
        if (!closed) {
            Arrays.fill(keyBytes, (byte) 0);
            closed = true;
        }
    }

    @Override
    public @NonNull String toString() {
        return "VaultKey[keyId=%s, keyBytes=[REDACTED %d bytes], closed=%s]"
                .formatted(keyId, keyBytes.length, closed);
    }

    private void requireOpen() {
        if (closed) {
            throw new SecretKeyDestroyedException();
        }
    }
}
