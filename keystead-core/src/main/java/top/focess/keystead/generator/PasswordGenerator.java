package top.focess.keystead.generator;

import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.SecretBuffer;

/**
 * Generates a password conforming to a {@link PasswordPolicy}, returning it as an owned {@link
 * SecretBuffer}.
 */
public interface PasswordGenerator {

    /**
     * Generates a password for the given policy.
     *
     * @param policy the password policy
     * @return the generated password
     */
    @NonNull SecretBuffer generate(@NonNull PasswordPolicy policy);
}
