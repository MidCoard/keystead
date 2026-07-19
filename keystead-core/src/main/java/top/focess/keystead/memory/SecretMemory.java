package top.focess.keystead.memory;

import java.util.function.Consumer;
import org.jspecify.annotations.NonNull;

/**
 * Owned secret byte storage with a defined wipe-on-close lifecycle. Implementations may lock pages
 * or exclude them from crash dumps in addition to wiping.
 */
public interface SecretMemory extends AutoCloseable {

    /**
     * Returns the number of secret bytes held.
     *
     * @return the number of secret bytes held
     * @throws SecretDestroyedException if this memory has been closed
     */
    int length();

    /**
     * Returns whether this memory has been closed and wiped.
     *
     * @return whether this memory has been closed and wiped
     */
    boolean isClosed();

    /**
     * Passes a copy of the secret bytes to {@code consumer}; the copy is wiped after the callback
     * returns.
     *
     * @param consumer callback receiving a transient copy of the secret bytes
     * @throws SecretDestroyedException if this memory has been closed
     */
    void copyBytes(@NonNull Consumer<byte[]> consumer);

    /** Wipes the secret bytes and releases any native resources. Closing twice is a no-op. */
    @Override
    void close();
}
