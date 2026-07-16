package top.focess.keystead.model;

import java.util.Objects;
import org.jspecify.annotations.NonNull;

/**
 * Stable identifier for a vault key generation.
 *
 * @param value the non-blank key id
 */
public record KeyId(@NonNull String value) {

    /** Validates the record components. */
    public KeyId {
        Objects.requireNonNull(value, "value");
        if (value.isBlank()) {
            throw new IllegalArgumentException("Key id must not be blank");
        }
    }
}
