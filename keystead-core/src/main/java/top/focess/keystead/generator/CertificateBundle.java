package top.focess.keystead.generator;

import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.SecretBuffer;

public final class CertificateBundle implements AutoCloseable {

    private final String certificate;
    private final SecretBuffer privateKey;

    public CertificateBundle(@NonNull String certificate, @NonNull SecretBuffer privateKey) {
        this.certificate = Objects.requireNonNull(certificate, "certificate");
        this.privateKey = Objects.requireNonNull(privateKey, "privateKey");
    }

    public @NonNull String certificate() {
        return certificate;
    }

    public @NonNull SecretBuffer privateKey() {
        return privateKey;
    }

    @Override
    public void close() {
        privateKey.close();
    }
}
