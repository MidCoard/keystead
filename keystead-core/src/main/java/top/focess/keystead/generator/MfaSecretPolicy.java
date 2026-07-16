package top.focess.keystead.generator;

import java.util.Objects;
import org.jspecify.annotations.NonNull;

/**
 * Policy for generating an MFA secret: issuer, account name, secret length, digits, and period.
 *
 * @param issuer the issuer name
 * @param accountName the account name
 * @param secretBytes the number of secret bytes; must be positive
 * @param digits the number of TOTP digits; between 6 and 8
 * @param periodSeconds the TOTP period in seconds; must be positive
 */
public record MfaSecretPolicy(
        @NonNull String issuer,
        @NonNull String accountName,
        int secretBytes,
        int digits,
        int periodSeconds) {

    /** Validates the record components. */
    public MfaSecretPolicy {
        issuer = normalize(issuer, "issuer");
        accountName = normalize(accountName, "accountName");
        if (secretBytes <= 0) {
            throw new IllegalArgumentException("MFA secret byte length must be positive");
        }
        if (digits < 6 || digits > 8) {
            throw new IllegalArgumentException("MFA digits must be between 6 and 8");
        }
        if (periodSeconds <= 0) {
            throw new IllegalArgumentException("MFA period must be positive");
        }
    }

    /** Returns a standard TOTP policy (20 secret bytes, 6 digits, 30 seconds).
     *
     * @param issuer the issuer name
     * @param accountName the account name
     * @return the standard TOTP policy */
    public static @NonNull MfaSecretPolicy totp(
            @NonNull String issuer, @NonNull String accountName) {
        return new MfaSecretPolicy(issuer, accountName, 20, 6, 30);
    }

    private static @NonNull String normalize(@NonNull String value, @NonNull String name) {
        String normalized = Objects.requireNonNull(value, name).trim();
        if (normalized.isBlank()) {
            throw new IllegalArgumentException("MFA " + name + " is required");
        }
        return normalized;
    }
}
