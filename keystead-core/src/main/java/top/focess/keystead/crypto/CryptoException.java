package top.focess.keystead.crypto;

import org.jspecify.annotations.NonNull;

public class CryptoException extends RuntimeException {

    public CryptoException(@NonNull String message) {
        super(message);
    }

    public CryptoException(@NonNull String message, @NonNull Throwable cause) {
        super(message, cause);
    }
}
