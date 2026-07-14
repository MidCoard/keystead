package top.focess.keystead.crypto;

import java.util.Objects;
import java.util.function.Consumer;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.SecretDestroyedException;
import top.focess.keystead.memory.SecretMemory;
import top.focess.keystead.memory.SecretMemoryProvider;
import top.focess.keystead.model.KeyId;

public final class VaultKey implements AutoCloseable {

    private final KeyId keyId;
    private final SecretMemory keyBytes;
    private final int keyBytesLength;

    VaultKey(@NonNull KeyId keyId, byte @NonNull [] keyBytes) {
        this(keyId, keyBytes, SecretMemoryProvider.heap());
    }

    VaultKey(
            @NonNull KeyId keyId,
            byte @NonNull [] keyBytes,
            @NonNull SecretMemoryProvider memoryProvider) {
        this.keyId = Objects.requireNonNull(keyId, "keyId");
        Objects.requireNonNull(keyBytes, "keyBytes");
        this.keyBytesLength = keyBytes.length;
        this.keyBytes =
                Objects.requireNonNull(
                        Objects.requireNonNull(memoryProvider, "memoryProvider").protect(keyBytes),
                        "protected memory");
    }

    public @NonNull KeyId keyId() {
        return keyId;
    }

    public boolean isClosed() {
        return keyBytes.isClosed();
    }

    public void copyBytes(@NonNull Consumer<byte[]> consumer) {
        try {
            keyBytes.copyBytes(Objects.requireNonNull(consumer, "consumer"));
        } catch (SecretDestroyedException e) {
            throw new SecretKeyDestroyedException();
        }
    }

    @Override
    public void close() {
        keyBytes.close();
    }

    @Override
    public @NonNull String toString() {
        return "VaultKey[keyId=%s, keyBytes=[REDACTED %d bytes], closed=%s]"
                .formatted(keyId, keyBytesLength, isClosed());
    }
}
