package top.focess.keystead.memory;

/**
 * Thrown when a {@link SecretBuffer} (or other owned secret value) is used after it has been closed
 * and its bytes wiped.
 */
public final class SecretDestroyedException extends IllegalStateException {

    public SecretDestroyedException() {
        super("Secret buffer has already been destroyed");
    }
}
