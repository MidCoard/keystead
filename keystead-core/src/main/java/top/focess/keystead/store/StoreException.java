package top.focess.keystead.store;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

public final class StoreException extends RuntimeException {

    public StoreException(@NonNull String message, @Nullable Throwable cause) {
        super(message, cause);
    }
}
