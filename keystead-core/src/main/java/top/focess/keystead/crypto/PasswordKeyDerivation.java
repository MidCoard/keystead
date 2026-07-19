package top.focess.keystead.crypto;

import org.jspecify.annotations.NonNull;

/** A password-based key-derivation function implementation. */
public interface PasswordKeyDerivation {

    /**
     * Returns the KDF algorithm name this implementation supports.
     *
     * @return the KDF algorithm name
     */
    @NonNull String algorithm();

    /**
     * Derives key bytes from a password.
     *
     * @param password caller-owned password; wiped by the caller
     * @param parameters the KDF parameters for {@link #algorithm()}
     * @param outputBytes the number of bytes to derive; must be positive
     * @return the derived key bytes
     */
    byte @NonNull [] derive(
            char @NonNull [] password, @NonNull KdfParameters parameters, int outputBytes);
}
