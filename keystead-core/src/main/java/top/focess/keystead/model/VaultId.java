package top.focess.keystead.model;

import java.util.Objects;
import java.util.UUID;

public record VaultId(UUID value) {

    public VaultId {
        Objects.requireNonNull(value, "value");
    }
}
