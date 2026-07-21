package top.focess.keystead.generator;

import java.time.Instant;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.SecretBuffer;

/**
 * Generates a time-based one-time password (RFC 6238 TOTP) code from an MFA seed.
 *
 * <p>The code is derived from the Base32 seed held in a {@link SecretBuffer} (the seed produced by
 * {@link MfaSecretGenerator}) and the {@link MfaSecretPolicy} digit/period settings. HMAC-SHA1 is
 * used, matching the {@code algorithm=SHA1} emitted in the {@code otpauth} URI; only the
 * {@link MfaSecretPolicy#digits()} and {@link MfaSecretPolicy#periodSeconds()} components affect
 * the code.
 *
 * <p>The returned character array is the numeric code and is itself sensitive: the caller owns it
 * and must wipe it when done. The seed is accessed only through {@link SecretBuffer#copyBytes} so
 * the protected copy is wiped after use.
 */
public interface TotpCodeGenerator {

    /**
     * Generates the TOTP code valid at the given instant.
     *
     * @param policy the MFA policy (digits and period are used)
     * @param seed the Base32 MFA seed
     * @param now the instant the code is valid for
     * @return a newly allocated character array holding the numeric code; the caller must wipe it
     */
    char @NonNull [] generate(
            @NonNull MfaSecretPolicy policy, @NonNull SecretBuffer seed, @NonNull Instant now);
}
