package top.focess.keystead.model;

import java.util.Objects;
import java.util.UUID;

public record SecretId(UUID value) {

    public SecretId {
        Objects.requireNonNull(value, "value");
    }
}
