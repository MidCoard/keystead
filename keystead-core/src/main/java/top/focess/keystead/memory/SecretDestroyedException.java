package top.focess.keystead.memory;

public final class SecretDestroyedException extends IllegalStateException {

    public SecretDestroyedException() {
        super("Secret buffer has already been destroyed");
    }
}
