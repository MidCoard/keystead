package top.focess.keystead.service;

import java.util.Optional;
import java.util.function.Consumer;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.SecretMetadata;

/**
 * Short-lived, decoded view of a login-password secret.
 *
 * <p>Character fields are exposed only inside a {@link Consumer} callback; the supplied {@code
 * char[]} is wiped when the callback returns, so callers must not retain it and should avoid
 * copying it into a {@link String}. The view is closed by {@link VaultHandle#withLogin} after the
 * callback completes.
 */
public interface LoginSecretView {

    /** @return the secret's non-secret metadata. */
    @NonNull SecretMetadata metadata();

    /** @return the optional URL, which is not treated as secret. */
    @NonNull Optional<String> url();

    /** Exposes the username characters inside the callback. */
    void withUsername(@NonNull Consumer<char[]> consumer);

    /** Exposes the password characters inside the callback. */
    void withPassword(@NonNull Consumer<char[]> consumer);

    /** Exposes the notes characters inside the callback. */
    void withNotes(@NonNull Consumer<char[]> consumer);
}
