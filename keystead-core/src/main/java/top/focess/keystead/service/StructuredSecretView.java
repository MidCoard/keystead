package top.focess.keystead.service;

import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.SecretMetadata;

/**
 * Short-lived, decoded view of a structured secret.
 *
 * <p>Field values are exposed only inside a {@link Consumer} callback; the supplied {@code char[]}
 * is wiped when the callback returns, so callers must not retain it and should avoid copying it
 * into a {@link String}. The view is closed by {@link VaultHandle#withSecret} after the callback
 * completes.
 */
public interface StructuredSecretView {

    /** @return the secret's non-secret metadata. */
    @NonNull SecretMetadata metadata();

    /** @return the names of every field present. */
    @NonNull Set<String> fieldNames();

    /** @return the names of every field present, in insertion order. */
    @NonNull List<String> orderedFieldNames();

    /** Exposes the named field's characters inside the callback. */
    void withField(@NonNull String name, @NonNull Consumer<char[]> consumer);
}
