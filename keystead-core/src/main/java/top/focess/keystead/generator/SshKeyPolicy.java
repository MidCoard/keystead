package top.focess.keystead.generator;

import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Policy for generating an SSH key: algorithm and optional comment.
 *
 * @param algorithm the SSH key algorithm
 * @param comment the optional key comment, or {@code null}
 */
public record SshKeyPolicy(@NonNull SshKeyAlgorithm algorithm, @Nullable String comment) {

    /** Validates the record components. */
    public SshKeyPolicy {
        Objects.requireNonNull(algorithm, "algorithm");
        comment = normalize(comment);
    }

    /** Returns an ED25519 policy with the given comment.
     *
     * @param comment the optional key comment, or {@code null}
     * @return the ED25519 SSH key policy */
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
