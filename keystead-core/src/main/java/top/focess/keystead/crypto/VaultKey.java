package top.focess.keystead.crypto;

import java.util.Objects;
import java.util.function.Consumer;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.SecretDestroyedException;
import top.focess.keystead.memory.SecretMemory;
import top.focess.keystead.memory.SecretMemoryProvider;
import top.focess.keystead.model.KeyId;
import top.focess.keystead.model.SecurityLimits;

/**
 * Owned, wipeable vault key material.
 *
 * <p>The key bytes are copied on construction and wiped on {@link #close()}; {@link #copyBytes}
 * hands a wiped copy to a callback; {@link #toString()} redacts the bytes. After close, access
 * throws {@link SecretKeyDestroyedException}.
 */
public final class VaultKey implements AutoCloseable {

    private final KeyId keyId;
    private final SecretMemory keyBytes;
    private final int keyBytesLength;

    VaultKey(@NonNull KeyId keyId, byte @NonNull [] keyBytes) {
        this(keyId, keyBytes, SecretMemoryProvider.systemDefault());
    }

    VaultKey(
            @NonNull KeyId keyId,
            byte @NonNull [] keyBytes,
            @NonNull SecretMemoryProvider memoryProvider) {
        this.keyId = Objects.requireNonNull(keyId, "keyId");
        Objects.requireNonNull(keyBytes, "keyBytes");
        if (keyBytes.length != SecurityLimits.AES_256_KEY_BYTES) {
            throw new IllegalArgumentException("Vault key must be exactly 32 bytes");
        }
        this.keyBytesLength = keyBytes.length;
        this.keyBytes =
                Objects.requireNonNull(
                        Objects.requireNonNull(memoryProvider, "memoryProvider").protect(keyBytes),
                        "protected memory");
    }

    /** @return the id of this key generation. */
    public @NonNull KeyId keyId() {
        return keyId;
    }

    /** @return whether this key has been closed and its bytes wiped. */
    public boolean isClosed() {
        return keyBytes.isClosed();
    }

    /**
     * Copies the key bytes and hands them to the callback; the copy is wiped when the callback
     * returns, so callers must not retain it.
     */
    public void copyBytes(@NonNull Consumer<byte[]> consumer) {
        try {
            keyBytes.copyBytes(Objects.requireNonNull(consumer, "consumer"));
        } catch (SecretDestroyedException e) {
            throw new SecretKeyDestroyedException();
        }
    }

    /** Wipes the key bytes. Closing an already-closed key is a no-op. */
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
