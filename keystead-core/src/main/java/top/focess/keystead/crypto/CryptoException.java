package top.focess.keystead.crypto;

import org.jspecify.annotations.NonNull;

/**
 * Thrown when a cryptographic operation fails, such as an unwrapping failure from a wrong password
 * or a corrupt or tampered ciphertext. The message never contains secret bytes.
 */
public class CryptoException extends RuntimeException {

    /** Creates an exception with a message.
     *
     * @param message the detail message */
    public CryptoException(@NonNull String message) {
        super(message);
    }

    /** Creates an exception with a message and cause.
     *
     * @param message the detail message
     * @param cause the cause */
    public CryptoException(@NonNull String message, @NonNull Throwable cause) {
        super(message, cause);
    }
}
