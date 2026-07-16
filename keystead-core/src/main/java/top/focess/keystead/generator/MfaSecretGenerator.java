package top.focess.keystead.generator;

import org.jspecify.annotations.NonNull;

/**
 * Generates an MFA secret and its {@code otpauth} URI conforming to a {@link MfaSecretPolicy}.
 */
public interface MfaSecretGenerator {

    /**
     * Generates an MFA secret for the given policy.
     *
     * @param policy the MFA secret policy
     * @return the generated MFA secret
     */
    @NonNull MfaSecret generate(@NonNull MfaSecretPolicy policy);
}
