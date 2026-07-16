package top.focess.keystead.crypto;

/**
 * Thrown when an owned key (such as a {@link VaultKey} or {@link DeviceKeyPair}) is used after it
 * has been closed and its key material wiped.
 */
public final class SecretKeyDestroyedException extends IllegalStateException {

    /** Constructs the exception. */
    public SecretKeyDestroyedException() {
        super("Secret key has already been destroyed");
    }
}
