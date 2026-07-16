package top.focess.keystead.generator;

import java.util.Objects;
import org.jspecify.annotations.NonNull;

/**
 * Policy for generating an API token: a URL-safe prefix and a random-byte length.
 *
 * @param prefix the URL-safe prefix prepended to the token
 * @param randomBytes the number of random bytes encoded into the token; must be positive
 */
public record ApiTokenPolicy(@NonNull String prefix, int randomBytes) {

    /** Validates the record components. */
    public ApiTokenPolicy {
        prefix = Objects.requireNonNull(prefix, "prefix").trim();
        if (prefix.isBlank()) {
            throw new IllegalArgumentException("API token prefix is required");
        }
        if (!prefix.matches("[A-Za-z0-9_-]+")) {
            throw new IllegalArgumentException("API token prefix must be URL-safe");
        }
        if (randomBytes <= 0) {
            throw new IllegalArgumentException("API token random byte length must be positive");
        }
    }

    /** Returns a policy matching the GitHub personal-access-token format ({@code ghp_} prefix).
     *
     * @return the GitHub token policy */
    public static @NonNull ApiTokenPolicy github() {
        return new ApiTokenPolicy("ghp", 32);
    }
}
