package top.focess.keystead.generator;

import java.util.Objects;
import org.jspecify.annotations.NonNull;

public record MfaSecretPolicy(
        @NonNull String issuer,
        @NonNull String accountName,
        int secretBytes,
        int digits,
        int periodSeconds) {

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
