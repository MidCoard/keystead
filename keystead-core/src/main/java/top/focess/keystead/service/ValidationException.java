package top.focess.keystead.service;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Thrown when a vault operation is rejected because its input or state is invalid, such as a
 * missing or unknown vault, a wrong secret type, an incomplete draft, a stale or mixed-vault sync
 * batch, or an unsupported algorithm. The message never contains secret bytes.
 */
public final class ValidationException extends RuntimeException {

    public ValidationException(@NonNull String message) {
        super(message);
    }

    public ValidationException(@NonNull String message, @Nullable Throwable cause) {
        super(message, cause);
    }
}
