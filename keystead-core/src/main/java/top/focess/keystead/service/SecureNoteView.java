package top.focess.keystead.service;

import java.util.function.Consumer;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.SecretMetadata;

/**
 * Short-lived, decoded view of a secure note.
 *
 * <p>The body is exposed only inside a {@link Consumer} callback; the supplied {@code char[]} is
 * wiped when the callback returns, so callers must not retain it and should avoid copying it into a
 * {@link String}. The view is closed by {@link VaultHandle#withSecureNote} after the callback
 * completes.
 */
public interface SecureNoteView {

    /** Returns the secret's non-secret metadata.
     *
     * @return the secret's non-secret metadata */
    @NonNull SecretMetadata metadata();

    /** Exposes the note body characters inside the callback.
     *
     * @param consumer callback that receives the body {@code char[]}; wiped after the call */
    void withBody(@NonNull Consumer<char[]> consumer);
}
