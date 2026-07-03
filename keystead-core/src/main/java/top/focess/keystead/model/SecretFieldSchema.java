package top.focess.keystead.model;

import java.util.Objects;
import org.jspecify.annotations.NonNull;

public record SecretFieldSchema(
        @NonNull String name, @NonNull SecretFieldType type, boolean required, boolean revealable) {

    public SecretFieldSchema {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(type, "type");
        if (name.isBlank()) {
            throw new IllegalArgumentException("Field name must not be blank");
        }
    }
}
