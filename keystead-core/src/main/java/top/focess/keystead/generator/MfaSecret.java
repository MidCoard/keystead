package top.focess.keystead.generator;

import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.SecretBuffer;

/**
 * Owned MFA seed and otpauth URI. Closing the secret closes (wipes) both {@link SecretBuffer}
 * instances.
 */
public final class MfaSecret implements AutoCloseable {

    private final SecretBuffer seed;
    private final SecretBuffer otpauthUri;

    /**
     * Creates an MFA secret from its seed and otpauth URI.
     *
     * @param seed the owned MFA seed
     * @param otpauthUri the owned otpauth URI
     */
    public MfaSecret(@NonNull SecretBuffer seed, @NonNull SecretBuffer otpauthUri) {
        this.seed = Objects.requireNonNull(seed, "seed");
        this.otpauthUri = Objects.requireNonNull(otpauthUri, "otpauthUri");
    }

    /** Returns the owned MFA seed.
     *
     * @return the owned MFA seed */
    public @NonNull SecretBuffer seed() {
        return seed;
    }

    /** Returns the owned otpauth URI.
     *
     * @return the owned otpauth URI */
    public @NonNull SecretBuffer otpauthUri() {
        return otpauthUri;
    }

    @Override
    public void close() {
        seed.close();
        otpauthUri.close();
    }

    @Override
    public @NonNull String toString() {
        return "MfaSecret(<redacted>)";
    }
}
