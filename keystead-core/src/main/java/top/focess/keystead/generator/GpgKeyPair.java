package top.focess.keystead.generator;

import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.SecretBuffer;

public final class GpgKeyPair implements AutoCloseable {

    private final String publicKey;
    private final SecretBuffer privateKey;

    public GpgKeyPair(@NonNull String publicKey, @NonNull SecretBuffer privateKey) {
        this.publicKey = Objects.requireNonNull(publicKey, "publicKey");
        this.privateKey = Objects.requireNonNull(privateKey, "privateKey");
    }

    public @NonNull String publicKey() {
        return publicKey;
    }

    public @NonNull SecretBuffer privateKey() {
        return privateKey;
    }

    @Override
    public void close() {
        privateKey.close();
    }
}
