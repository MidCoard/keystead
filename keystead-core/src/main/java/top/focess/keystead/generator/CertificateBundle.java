package top.focess.keystead.generator;

import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.SecretBuffer;

/**
 * Owned X.509 certificate and its private key. Closing the bundle closes (wipes) the private key's
 * {@link SecretBuffer}.
 */
public final class CertificateBundle implements AutoCloseable {

    private final String certificate;
    private final SecretBuffer privateKey;

    /**
     * Creates a bundle from a PEM certificate and its private key.
     *
     * @param certificate the PEM-encoded certificate
     * @param privateKey the owned private key
     */
    public CertificateBundle(@NonNull String certificate, @NonNull SecretBuffer privateKey) {
        this.certificate = Objects.requireNonNull(certificate, "certificate");
        this.privateKey = Objects.requireNonNull(privateKey, "privateKey");
    }

    /** Returns the PEM-encoded certificate.
     *
     * @return the PEM-encoded certificate */
    public @NonNull String certificate() {
        return certificate;
    }

    /** Returns the owned private key.
     *
     * @return the owned private key */
    public @NonNull SecretBuffer privateKey() {
        return privateKey;
    }

    @Override
    public void close() {
        privateKey.close();
    }
}
