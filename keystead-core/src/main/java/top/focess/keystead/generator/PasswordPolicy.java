package top.focess.keystead.generator;

import java.util.Objects;
import java.util.Set;
import org.jspecify.annotations.NonNull;

/**
 * Policy for generating a password: length, character-class toggles, ambiguous-character avoidance,
 * and excluded characters.
 *
 * @param length the password length; must be positive
 * @param uppercase whether uppercase letters are included
 * @param lowercase whether lowercase letters are included
 * @param digits whether digits are included
 * @param symbols whether symbols are included
 * @param avoidAmbiguous whether to avoid visually ambiguous characters
 * @param excludedCharacters the characters to exclude
 */
public record PasswordPolicy(
        int length,
        boolean uppercase,
        boolean lowercase,
        boolean digits,
        boolean symbols,
        boolean avoidAmbiguous,
        @NonNull Set<Character> excludedCharacters) {

    /** Validates the record components. */
    public PasswordPolicy {
        if (length <= 0) {
            throw new IllegalArgumentException("Password length must be positive");
        }
        excludedCharacters =
                Set.copyOf(Objects.requireNonNull(excludedCharacters, "excludedCharacters"));
    }
}
