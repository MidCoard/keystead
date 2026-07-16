package top.focess.keystead.model;

import java.util.Objects;
import java.util.UUID;
import org.jspecify.annotations.NonNull;

/**
 * Stable identifier for a vault.
 *
 * @param value the unique vault id
 */
public record VaultId(@NonNull UUID value) {

    /** Validates the record components. */
    public VaultId {
        Objects.requireNonNull(value, "value");
    }
}
