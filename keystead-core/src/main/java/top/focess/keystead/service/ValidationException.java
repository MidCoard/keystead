package top.focess.keystead.service;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

public final class ValidationException extends RuntimeException {

    public ValidationException(@NonNull String message) {
        super(message);
    }

    public ValidationException(@NonNull String message, @Nullable Throwable cause) {
        super(message, cause);
    }
}
