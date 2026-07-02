package top.focess.keystead.crypto;

public final class SecretKeyDestroyedException extends IllegalStateException {

    public SecretKeyDestroyedException() {
        super("Secret key has already been destroyed");
    }
}
