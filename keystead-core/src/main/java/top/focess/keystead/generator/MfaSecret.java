package top.focess.keystead.generator;

import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.SecretBuffer;

public final class MfaSecret implements AutoCloseable {

    private final SecretBuffer seed;
    private final SecretBuffer otpauthUri;

    public MfaSecret(@NonNull SecretBuffer seed, @NonNull SecretBuffer otpauthUri) {
        this.seed = Objects.requireNonNull(seed, "seed");
        this.otpauthUri = Objects.requireNonNull(otpauthUri, "otpauthUri");
    }

    public @NonNull SecretBuffer seed() {
        return seed;
    }

    public @NonNull SecretBuffer otpauthUri() {
        return otpauthUri;
    }

    @Override
    public void close() {
        seed.close();
        otpauthUri.close();
    }
}
