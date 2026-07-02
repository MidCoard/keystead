package top.focess.keystead.generator;

import java.util.Objects;
import java.util.Set;
import org.jspecify.annotations.NonNull;

public record PasswordPolicy(
        int length,
        boolean uppercase,
        boolean lowercase,
        boolean digits,
        boolean symbols,
        boolean avoidAmbiguous,
        @NonNull Set<Character> excludedCharacters) {

    public PasswordPolicy {
        if (length <= 0) {
            throw new IllegalArgumentException("Password length must be positive");
        }
        excludedCharacters =
                Set.copyOf(Objects.requireNonNull(excludedCharacters, "excludedCharacters"));
    }
}
