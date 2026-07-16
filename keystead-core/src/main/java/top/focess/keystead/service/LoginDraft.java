package top.focess.keystead.service;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.model.SecretClassification;

/**
 * Fluent builder for a login-password secret draft.
 *
 * <p>Secret fields ({@link #username}, {@link #password}, {@link #notes}) copy bytes from the
 * supplied {@link SecretBuffer} and are owned by the draft; the draft wipes them when it is closed.
 * A draft is validated and closed by {@link VaultHandle#saveLogin} and {@link
 * VaultHandle#updateLogin}, so callers usually do not close it themselves.
 */
public interface LoginDraft {

    /** Sets the required, human-readable title.
     *
     * @param title the human-readable title
     * @return this draft */
    @NonNull LoginDraft title(@NonNull String title);

    /** Adds a free-form tag; blank values are ignored. May be called more than once.
     *
     * @param tag the tag to add, or {@code null}
     * @return this draft */
    @NonNull LoginDraft tag(@Nullable String tag);

    /** Sets the classification taxonomy; defaults to none.
     *
     * @param classification the classification taxonomy
     * @return this draft */
    @NonNull LoginDraft classification(@NonNull SecretClassification classification);

    /**
     * Associates a custom attribute with the key, replacing any existing value; blank keys or values
     * are ignored.
     *
     * @param key the attribute key
     * @param value the attribute value
     * @return this draft
     */
    @NonNull LoginDraft attribute(@NonNull String key, @NonNull String value);

    /** Sets the username, copying and owning its bytes.
     *
     * @param username the username buffer; copied and owned by this draft
     * @return this draft */
    @NonNull LoginDraft username(@NonNull SecretBuffer username);

    /** Sets the required password, copying and owning its bytes.
     *
     * @param password the password buffer; copied and owned by this draft
     * @return this draft */
    @NonNull LoginDraft password(@NonNull SecretBuffer password);

    /** Sets the optional URL, which is not treated as secret.
     *
     * @param url the URL, or {@code null}
     * @return this draft */
    @NonNull LoginDraft url(@Nullable String url);

    /** Sets the optional notes, copying and owning its bytes.
     *
     * @param notes the notes buffer; copied and owned by this draft
     * @return this draft */
    @NonNull LoginDraft notes(@NonNull SecretBuffer notes);
}
