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

    /** Sets the required, human-readable title. */
    @NonNull StructuredSecretDraft title(@NonNull String title);

    /** Adds a free-form tag; blank values are ignored. May be called more than once. */
    @NonNull StructuredSecretDraft tag(@Nullable String tag);

    /** Sets the classification taxonomy; defaults to none. */
    @NonNull StructuredSecretDraft classification(@NonNull SecretClassification classification);

    /**
     * Associates a custom attribute with the key, replacing any existing value; blank keys or values
     * are ignored.
     */
    @NonNull StructuredSecretDraft attribute(@NonNull String key, @NonNull String value);

    /**
     * Sets a named field, copying and owning its bytes. The name is stripped; a blank name is
     * ignored. Reusing a name replaces and wipes the previous value. At least one field is required.
     */
    @NonNull StructuredSecretDraft field(@NonNull String name, @NonNull SecretBuffer value);
}
