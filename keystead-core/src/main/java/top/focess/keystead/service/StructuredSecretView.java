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

    /** Returns the secret's non-secret metadata.
     *
     * @return the secret's non-secret metadata */
    @NonNull SecretMetadata metadata();

    /** Returns the names of every field present.
     *
     * @return the names of every field present */
    @NonNull Set<String> fieldNames();

    /** Returns the names of every field present, in insertion order.
     *
     * @return the names of every field present, in insertion order */
    @NonNull List<String> orderedFieldNames();

    /** Exposes the named field's characters inside the callback.
     *
     * @param name the field name
     * @param consumer callback that receives the field's {@code char[]}; wiped after the call */
    void withField(@NonNull String name, @NonNull Consumer<char[]> consumer);
}
