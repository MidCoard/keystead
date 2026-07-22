package top.focess.keystead.generator;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import top.focess.keystead.memory.SecretBuffer;

class DefaultPasswordGeneratorTest {

    private final PasswordGenerator generator = new DefaultPasswordGenerator();

    @Test
    void rejectsPolicyWithNoCharacterGroups() {
        PasswordPolicy policy = new PasswordPolicy(16, false, false, false, false, false, Set.of());

        assertThrows(IllegalArgumentException.class, () -> generator.generate(policy));
    }

    @Test
    void generatedPasswordHasRequestedLengthAndRequiredGroups() {
        PasswordPolicy policy = new PasswordPolicy(32, true, true, true, true, false, Set.of());

        try (SecretBuffer password = generator.generate(policy)) {
            AtomicReference<char[]> seen = new AtomicReference<>();
            password.copyChars(chars -> seen.set(chars.clone()));

            char[] chars = seen.get();
            assertEquals(32, chars.length);
            assertTrue(containsAny(chars, 'A', 'Z'));
            assertTrue(containsAny(chars, 'a', 'z'));
            assertTrue(containsAny(chars, '0', '9'));
            assertTrue(containsSymbol(chars));
        }
    }

    @Test
    void generatedPasswordExcludesConfiguredCharacters() {
        PasswordPolicy policy =
                new PasswordPolicy(48, false, true, false, false, false, Set.of('a', 'b', 'c'));

        try (SecretBuffer password = generator.generate(policy)) {
            password.copyChars(
                    chars -> {
                        assertEquals(48, chars.length);
                        for (char c : chars) {
                            assertTrue(c >= 'd' && c <= 'z', "unexpected character: " + c);
                        }
                    });
        }
    }

    @Test
    void generatedPasswordCanAvoidAmbiguousCharacters() {
        PasswordPolicy policy = new PasswordPolicy(48, true, true, true, false, true, Set.of());

        try (SecretBuffer password = generator.generate(policy)) {
            password.copyChars(
                    chars -> {
                        for (char c : chars) {
                            assertFalse("0O1Il".indexOf(c) >= 0, "ambiguous character: " + c);
                        }
                    });
        }
    }

    @Test
    void rejectsPasswordLengthShorterThanEnabledGroupCount() {
        PasswordPolicy policy = new PasswordPolicy(3, true, true, true, true, false, Set.of());

        assertThrows(IllegalArgumentException.class, () -> generator.generate(policy));
    }

    private static boolean containsAny(char[] chars, char start, char end) {
        for (char c : chars) {
            if (c >= start && c <= end) {
                return true;
            }
        }
        return false;
    }

    private static boolean containsSymbol(char[] chars) {
        for (char c : chars) {
            if ("!@#$%^&*()-_=+[]{};:,.?/".indexOf(c) >= 0) {
                return true;
            }
        }
        return false;
    }
}
