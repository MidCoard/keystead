package top.focess.keystead.store;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Thrown when a {@link VaultStore} operation fails for a persistence reason, such as a vault
 * directory already belonging to another vault or a header timestamp moving backwards. The message
 * never contains secret bytes.
 */
public final class StoreException extends RuntimeException {

    /**
     * Creates a store exception with the given message and cause.
     *
     * @param message the non-secret detail message
     * @param cause the underlying cause, or {@code null} if none
     */
    public StoreException(@NonNull String message, @Nullable Throwable cause) {
        super(message, cause);
    }
}
