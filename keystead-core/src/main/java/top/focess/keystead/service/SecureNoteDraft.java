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

    /** Sets the required, human-readable title.
     *
     * @param title the human-readable title
     * @return this draft */
    @NonNull SecureNoteDraft title(@NonNull String title);

    /** Adds a free-form tag; blank values are ignored. May be called more than once.
     *
     * @param tag the tag to add, or {@code null}
     * @return this draft */
    @NonNull SecureNoteDraft tag(@Nullable String tag);

    /** Sets the classification taxonomy; defaults to none.
     *
     * @param classification the classification taxonomy
     * @return this draft */
    @NonNull SecureNoteDraft classification(@NonNull SecretClassification classification);

    /**
     * Associates a custom attribute with the key, replacing any existing value; blank keys or values
     * are ignored.
     *
     * @param key the attribute key
     * @param value the attribute value
     * @return this draft
     */
    @NonNull SecureNoteDraft attribute(@NonNull String key, @NonNull String value);

    /** Sets the required note body, copying and owning its bytes.
     *
     * @param body the note body buffer; copied and owned by this draft
     * @return this draft */
    @NonNull SecureNoteDraft body(@NonNull SecretBuffer body);
}
