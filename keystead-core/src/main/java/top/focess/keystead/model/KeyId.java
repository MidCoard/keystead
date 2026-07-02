package top.focess.keystead.model;

import java.util.Objects;
import org.jspecify.annotations.NonNull;

public record KeyId(@NonNull String value) {

    public KeyId {
        Objects.requireNonNull(value, "value");
        if (value.isBlank()) {
            throw new IllegalArgumentException("Key id must not be blank");
        }
    }
}
