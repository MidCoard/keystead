package top.focess.keystead.generator;

import org.jspecify.annotations.NonNull;

/**
 * Generates an OpenPGP key pair conforming to a {@link GpgKeyPolicy}.
 */
public interface GpgKeyGenerator {

    /**
     * Generates an OpenPGP key pair for the given policy.
     *
     * @param policy the GPG key policy
     * @return the generated key pair
     */
    @NonNull GpgKeyPair generate(@NonNull GpgKeyPolicy policy);
}
