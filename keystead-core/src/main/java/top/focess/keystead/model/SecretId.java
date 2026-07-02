package top.focess.keystead.model;

import java.util.Objects;
import java.util.UUID;
import org.jspecify.annotations.NonNull;

public record SecretId(@NonNull UUID value) {

    public SecretId {
        Objects.requireNonNull(value, "value");
    }
}
