package top.focess.keystead.generator;

import java.util.Objects;
import java.util.Set;

public record PasswordPolicy(
    int length,
    boolean uppercase,
    boolean lowercase,
    boolean digits,
    boolean symbols,
    boolean avoidAmbiguous,
    Set<Character> excludedCharacters
) {

    public PasswordPolicy {
        if (length <= 0) {
            throw new IllegalArgumentException("Password length must be positive");
        }
        excludedCharacters = Set.copyOf(Objects.requireNonNull(excludedCharacters, "excludedCharacters"));
    }
}
