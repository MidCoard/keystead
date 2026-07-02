package top.focess.keystead.service;

import org.jspecify.annotations.NonNull;

public final class ValidationException extends RuntimeException {

    public ValidationException(@NonNull String message) {
        super(message);
    }
}
