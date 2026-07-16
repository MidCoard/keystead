package top.focess.keystead.store;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Thrown when a {@link VaultStore} operation fails for a persistence reason, such as a vault
 * directory already belonging to another vault or a header timestamp moving backwards. The message
 * never contains secret bytes.
 */
public final class StoreException extends RuntimeException {

    public StoreException(@NonNull String message, @Nullable Throwable cause) {
        super(message, cause);
    }
}
