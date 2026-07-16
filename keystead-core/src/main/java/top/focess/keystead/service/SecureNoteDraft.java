package top.focess.keystead.service;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.model.SecretClassification;

/**
 * Fluent builder for a secure-note draft.
 *
 * <p>The {@link #body} copies bytes from the supplied {@link SecretBuffer} and is owned by the
 * draft; the draft wipes them when closed. A draft is validated and closed by {@link
 * VaultHandle#saveSecureNote}.
 */
public interface SecureNoteDraft {

    /** Sets the required, human-readable title. */
    @NonNull SecureNoteDraft title(@NonNull String title);

    /** Adds a free-form tag; blank values are ignored. May be called more than once. */
    @NonNull SecureNoteDraft tag(@Nullable String tag);

    /** Sets the classification taxonomy; defaults to none. */
    @NonNull SecureNoteDraft classification(@NonNull SecretClassification classification);

    /**
     * Associates a custom attribute with the key, replacing any existing value; blank keys or values
     * are ignored.
     */
    @NonNull SecureNoteDraft attribute(@NonNull String key, @NonNull String value);

    /** Sets the required note body, copying and owning its bytes. */
    @NonNull SecureNoteDraft body(@NonNull SecretBuffer body);
}
