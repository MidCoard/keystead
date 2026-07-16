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

    /** Sets the required, human-readable title. */
    @NonNull LoginDraft title(@NonNull String title);

    /** Adds a free-form tag; blank values are ignored. May be called more than once. */
    @NonNull LoginDraft tag(@Nullable String tag);

    /** Sets the classification taxonomy; defaults to none. */
    @NonNull LoginDraft classification(@NonNull SecretClassification classification);

    /**
     * Associates a custom attribute with the key, replacing any existing value; blank keys or values
     * are ignored.
     */
    @NonNull LoginDraft attribute(@NonNull String key, @NonNull String value);

    /** Sets the username, copying and owning its bytes. */
    @NonNull LoginDraft username(@NonNull SecretBuffer username);

    /** Sets the required password, copying and owning its bytes. */
    @NonNull LoginDraft password(@NonNull SecretBuffer password);

    /** Sets the optional URL, which is not treated as secret. */
    @NonNull LoginDraft url(@Nullable String url);

    /** Sets the optional notes, copying and owning its bytes. */
    @NonNull LoginDraft notes(@NonNull SecretBuffer notes);
}
