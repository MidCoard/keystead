package top.focess.keystead.generator;

import java.util.Objects;
import org.jspecify.annotations.NonNull;

public record ApiTokenPolicy(@NonNull String prefix, int randomBytes) {

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

    public static @NonNull ApiTokenPolicy github() {
        return new ApiTokenPolicy("ghp", 32);
    }
}
