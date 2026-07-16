package top.focess.keystead.service;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.model.SecretClassification;

/**
 * Fluent builder for a structured secret draft (SSH key, API token, GPG key, MFA seed, certificate,
 * or generic secret).
 *
 * <p>Field values copy bytes from the supplied {@link SecretBuffer} and are owned by the draft; the
 * draft wipes them when closed. A draft is validated and closed by {@link VaultHandle#saveSecret}
 * and {@link VaultHandle#updateSecret}.
 */
public interface StructuredSecretDraft {

    /** Sets the required, human-readable title.
     *
     * @param title the human-readable title
     * @return this draft */
    @NonNull StructuredSecretDraft title(@NonNull String title);

    /** Adds a free-form tag; blank values are ignored. May be called more than once.
     *
     * @param tag the tag to add, or {@code null}
     * @return this draft */
    @NonNull StructuredSecretDraft tag(@Nullable String tag);

    /** Sets the classification taxonomy; defaults to none.
     *
     * @param classification the classification taxonomy
     * @return this draft */
    @NonNull StructuredSecretDraft classification(@NonNull SecretClassification classification);

    /**
     * Associates a custom attribute with the key, replacing any existing value; blank keys or values
     * are ignored.
     *
     * @param key the attribute key
     * @param value the attribute value
     * @return this draft
     */
    @NonNull StructuredSecretDraft attribute(@NonNull String key, @NonNull String value);

    /**
     * Sets a named field, copying and owning its bytes. The name is stripped; a blank name is
     * ignored. Reusing a name replaces and wipes the previous value. At least one field is required.
     *
     * @param name the field name
     * @param value the field value buffer; copied and owned by this draft
     * @return this draft
     */
    @NonNull StructuredSecretDraft field(@NonNull String name, @NonNull SecretBuffer value);
}
