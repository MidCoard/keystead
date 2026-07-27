package top.focess.keystead.share;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import top.focess.keystead.service.ValidationException;

class SharePassphrasePolicyTest {

    @Test
    void rejectsTooShort() {
        ValidationException ex =
                assertThrows(
                        ValidationException.class,
                        () -> SharePassphrasePolicy.requireAcceptable("Ab3!Ab3!Ab".toCharArray()));
        assertTrue(ex.getMessage().toLowerCase().contains("characters"));
    }

    @Test
    void rejectsSingleCharacterClass() {
        // 12 lowercase letters: length is acceptable but only one character class.
        ValidationException ex =
                assertThrows(
                        ValidationException.class,
                        () ->
                                SharePassphrasePolicy.requireAcceptable(
                                        "abcdefghijkl".toCharArray()));
        assertTrue(ex.getMessage().toLowerCase().contains("character classes"));
    }

    @Test
    void rejectsTwoCharacterClasses() {
        // 12 chars, lower + digit only.
        assertThrows(
                ValidationException.class,
                () -> SharePassphrasePolicy.requireAcceptable("abcdefgh1234".toCharArray()));
    }

    @Test
    void acceptsThreeCharacterClasses() {
        // 12 chars, lower + upper + digit.
        assertDoesNotThrow(
                () -> SharePassphrasePolicy.requireAcceptable("Abcdefgh1234".toCharArray()));
    }

    @Test
    void acceptsFourCharacterClasses() {
        assertDoesNotThrow(
                () -> SharePassphrasePolicy.requireAcceptable("CorrectHorse42!".toCharArray()));
    }

    @Test
    void rejectsNull() {
        assertThrows(
                NullPointerException.class, () -> SharePassphrasePolicy.requireAcceptable(null));
    }
}
