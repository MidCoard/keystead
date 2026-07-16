package top.focess.keystead.crypto;

import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.SecretDestroyedException;
import top.focess.keystead.memory.SecretMemory;
import top.focess.keystead.memory.SecretMemoryProvider;

/**
 * Owned, wipeable device key pair used to wrap or unwrap vault keys for a device.
 *
 * <p>Both keys are copied on construction; {@link #close()} wipes the private key. {@link
 * #privateKey()} throws {@link SecretKeyDestroyedException} after close. {@link #toString()}
 * redacts both keys.
 */
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

    /** @return the device key algorithm name. */
    public @NonNull String keyAlgorithm() {
        return keyAlgorithm;
    }

    /** @return a defensive copy of the public key. */
    public byte @NonNull [] publicKey() {
        return Arrays.copyOf(publicKey, publicKey.length);
    }

    /**
     * Returns a defensive copy of the private key.
     *
     * @return a defensive copy of the private key.
     * @deprecated prefer {@link #copyPrivateKey(Consumer)} so the private key is handed to a
     *     callback instead of being copied into a caller-retained array; this accessor remains for
     *     compatibility.
     */
    @Deprecated(forRemoval = false)
    public byte @NonNull [] privateKey() {
        AtomicReference<byte[]> copy = new AtomicReference<>();
        copyPrivateKey(bytes -> copy.set(Arrays.copyOf(bytes, bytes.length)));
        return copy.get();
    }

    /**
     * Passes the private key bytes to {@code consumer} without returning a retained copy.
     *
     * @param consumer callback receiving the private key bytes.
     * @throws SecretKeyDestroyedException if this pair has been closed and the private key wiped.
     */
    public void copyPrivateKey(@NonNull Consumer<byte[]> consumer) {
        try {
            privateKey.copyBytes(Objects.requireNonNull(consumer, "consumer"));
        } catch (SecretDestroyedException e) {
            throw new SecretKeyDestroyedException();
        }
    }

    /** @return whether this pair has been closed and its private key wiped. */
    public boolean isClosed() {
        return privateKey.isClosed();
    }

    /** Wipes the private key. The public key is not sensitive. Closing twice is a no-op. */
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
