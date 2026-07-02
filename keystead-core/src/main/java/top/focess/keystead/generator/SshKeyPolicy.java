package top.focess.keystead.generator;

import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

public record SshKeyPolicy(@NonNull SshKeyAlgorithm algorithm, @Nullable String comment) {

    public SshKeyPolicy {
        Objects.requireNonNull(algorithm, "algorithm");
        comment = normalize(comment);
    }

    public static @NonNull SshKeyPolicy ed25519(@Nullable String comment) {
        return new SshKeyPolicy(SshKeyAlgorithm.ED25519, comment);
    }

    private static @Nullable String normalize(@Nullable String value) {
        if (value == null) {
            return null;
        }
        String normalized = value.trim();
        return normalized.isBlank() ? null : normalized;
    }
}
