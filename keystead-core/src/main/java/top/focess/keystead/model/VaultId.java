package top.focess.keystead.model;

import java.util.Objects;
import java.util.UUID;
import org.jspecify.annotations.NonNull;

public record VaultId(@NonNull UUID value) {

    public VaultId {
        Objects.requireNonNull(value, "value");
    }
}
