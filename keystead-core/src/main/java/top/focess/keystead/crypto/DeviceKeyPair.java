package top.focess.keystead.crypto;

import java.util.Arrays;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

public final class DeviceKeyPair implements AutoCloseable {

    private final String keyAlgorithm;
    private final byte[] publicKey;
    private final byte[] privateKey;
    private boolean closed;

    DeviceKeyPair(
            @NonNull String keyAlgorithm, byte @NonNull [] publicKey, byte @NonNull [] privateKey) {
        this.keyAlgorithm = Objects.requireNonNull(keyAlgorithm, "keyAlgorithm");
        this.publicKey =
                Arrays.copyOf(Objects.requireNonNull(publicKey, "publicKey"), publicKey.length);
        this.privateKey =
                Arrays.copyOf(Objects.requireNonNull(privateKey, "privateKey"), privateKey.length);
    }

    public @NonNull String keyAlgorithm() {
        return keyAlgorithm;
    }

    public byte @NonNull [] publicKey() {
        return Arrays.copyOf(publicKey, publicKey.length);
    }

    public byte @NonNull [] privateKey() {
        requireOpen();
        return Arrays.copyOf(privateKey, privateKey.length);
    }

    public boolean isClosed() {
        return closed;
    }

    @Override
    public void close() {
        if (!closed) {
            Arrays.fill(privateKey, (byte) 0);
            closed = true;
        }
    }

    @Override
    public @NonNull String toString() {
        return "DeviceKeyPair[keyAlgorithm=%s, publicKey=[REDACTED %d bytes], privateKey=[REDACTED %d bytes], closed=%s]"
                .formatted(keyAlgorithm, publicKey.length, privateKey.length, closed);
    }

    private void requireOpen() {
        if (closed) {
            throw new SecretKeyDestroyedException();
        }
    }
}
