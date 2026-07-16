package top.focess.keystead.generator;

import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.SecretBuffer;

/**
 * Owned SSH public/private key pair. Closing the pair closes (wipes) the private key's
 * {@link SecretBuffer}.
 */
public final class SshKeyPair implements AutoCloseable {

    private final String publicKey;
    private final SecretBuffer privateKey;

    /**
     * Creates a pair from an SSH public key and its owned private key.
     *
     * @param publicKey the SSH public key
     * @param privateKey the owned private key
     */
    public SshKeyPair(@NonNull String publicKey, @NonNull SecretBuffer privateKey) {
        this.publicKey = Objects.requireNonNull(publicKey, "publicKey");
        this.privateKey = Objects.requireNonNull(privateKey, "privateKey");
    }

    /** Returns the SSH public key.
     *
     * @return the SSH public key */
    public @NonNull String publicKey() {
        return publicKey;
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
