package top.focess.keystead.model;

import java.util.Objects;
import java.util.UUID;
import org.jspecify.annotations.NonNull;

/**
 * Stable identifier for a secret within a vault.
 *
 * @param value the unique secret id
 */
public record SecretId(@NonNull UUID value) {

    /** Validates the record components. */
    public SecretId {
        Objects.requireNonNull(value, "value");
    }
}
