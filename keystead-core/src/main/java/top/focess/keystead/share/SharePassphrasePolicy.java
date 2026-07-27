package top.focess.keystead.share;

import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.SecurityLimits;
import top.focess.keystead.service.ValidationException;

/**
 * Enforces the minimum strength of a share's temp passphrase at mint time.
 *
 * <p>A share string is self-contained and may be leaked (pasted into the wrong channel,
 * recovered from a clipboard, etc.). The temp passphrase is the only key protecting it, so
 * a composition floor bounds offline brute-force of a leaked share. The floor requires a
 * minimum length and at least a configurable number of character classes (lower, upper,
 * digit, symbol).
 *
 * <p>Package-private; invoked by {@link ShareService#create(ShareDraft, char[])}.
 */
final class SharePassphrasePolicy {

    static void requireAcceptable(char @NonNull [] passphrase) {
        Objects.requireNonNull(passphrase, "passphrase");
        if (passphrase.length < SecurityLimits.SHARE_PASSPHRASE_MIN_CHARACTERS) {
            throw new ValidationException(
                    "Share passphrase must be at least "
                            + SecurityLimits.SHARE_PASSPHRASE_MIN_CHARACTERS
                            + " characters");
        }
        boolean lower = false;
        boolean upper = false;
        boolean digit = false;
        boolean symbol = false;
        for (char c : passphrase) {
            if (Character.isLowerCase(c)) {
                lower = true;
            } else if (Character.isUpperCase(c)) {
                upper = true;
            } else if (Character.isDigit(c)) {
                digit = true;
            } else if (!Character.isWhitespace(c) && !Character.isISOControl(c)) {
                // Whitespace and control characters do not count toward the symbol class: a space
                // is a single extra code point and would otherwise let a two-class passphrase
                // satisfy the composition floor cheaply.
                symbol = true;
            }
        }
        int classes = 0;
        if (lower) {
            classes++;
        }
        if (upper) {
            classes++;
        }
        if (digit) {
            classes++;
        }
        if (symbol) {
            classes++;
        }
        if (classes < SecurityLimits.SHARE_PASSPHRASE_MIN_CHAR_CLASSES) {
            throw new ValidationException(
                    "Share passphrase must use at least "
                            + SecurityLimits.SHARE_PASSPHRASE_MIN_CHAR_CLASSES
                            + " character classes");
        }
    }

    private SharePassphrasePolicy() {
        throw new AssertionError("No instances");
    }
}
