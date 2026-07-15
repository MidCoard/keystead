package top.focess.keystead.crypto;

import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.SecretDestroyedException;
import top.focess.keystead.memory.SecretMemory;
import top.focess.keystead.memory.SecretMemoryProvider;

public final class DeviceKeyPair implements AutoCloseable {

    private final String keyAlgorithm;
    private final byte[] publicKey;
    private final SecretMemory privateKey;
    private final int privateKeyLength;

    DeviceKeyPair(
            @NonNull String keyAlgorithm, byte @NonNull [] publicKey, byte @NonNull [] privateKey) {
        this(keyAlgorithm, publicKey, privateKey, SecretMemoryProvider.systemDefault());
    }

    DeviceKeyPair(
            @NonNull String keyAlgorithm,
            byte @NonNull [] publicKey,
            byte @NonNull [] privateKey,
            @NonNull SecretMemoryProvider memoryProvider) {
        this.keyAlgorithm = Objects.requireNonNull(keyAlgorithm, "keyAlgorithm");
        this.publicKey =
                Arrays.copyOf(Objects.requireNonNull(publicKey, "publicKey"), publicKey.length);
        Objects.requireNonNull(privateKey, "privateKey");
        this.privateKeyLength = privateKey.length;
        this.privateKey =
                Objects.requireNonNull(
                        Objects.requireNonNull(memoryProvider, "memoryProvider")
                                .protect(privateKey),
                        "protected memory");
    }

    public @NonNull String keyAlgorithm() {
        return keyAlgorithm;
    }

    public byte @NonNull [] publicKey() {
        return Arrays.copyOf(publicKey, publicKey.length);
    }

    @Deprecated(forRemoval = false)
    public byte @NonNull [] privateKey() {
        AtomicReference<byte[]> copy = new AtomicReference<>();
        copyPrivateKey(bytes -> copy.set(Arrays.copyOf(bytes, bytes.length)));
        return copy.get();
    }

    public void copyPrivateKey(@NonNull Consumer<byte[]> consumer) {
        try {
            privateKey.copyBytes(Objects.requireNonNull(consumer, "consumer"));
        } catch (SecretDestroyedException e) {
            throw new SecretKeyDestroyedException();
        }
    }

    public boolean isClosed() {
        return privateKey.isClosed();
    }

    @Override
    public void close() {
        privateKey.close();
    }

    @Override
    public @NonNull String toString() {
        return "DeviceKeyPair[keyAlgorithm=%s, publicKey=[REDACTED %d bytes], privateKey=[REDACTED %d bytes], closed=%s]"
                .formatted(keyAlgorithm, publicKey.length, privateKeyLength, isClosed());
    }
}
