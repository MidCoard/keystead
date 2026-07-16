package top.focess.keystead.generator;

import org.jspecify.annotations.NonNull;

/**
 * Generates an SSH key pair conforming to a {@link SshKeyPolicy}.
 */
public interface SshKeyGenerator {

    /**
     * Generates an SSH key pair for the given policy.
     *
     * @param policy the SSH key policy
     * @return the generated key pair
     */
    @NonNull SshKeyPair generate(@NonNull SshKeyPolicy policy);
}
