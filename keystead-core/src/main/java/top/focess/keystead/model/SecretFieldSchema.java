package top.focess.keystead.model;

import java.util.List;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

public record SecretFieldSchema(
        @NonNull String name,
        @NonNull SecretFieldType type,
        boolean required,
        boolean revealable,
        @NonNull List<String> importAliases,
        @NonNull String exportName,
        @Nullable Integer maxLength) {

    public SecretFieldSchema(
            @NonNull String name,
            @NonNull SecretFieldType type,
            boolean required,
            boolean revealable) {
        this(name, type, required, revealable, List.of(), name, null);
    }

    public SecretFieldSchema {
        name = Objects.requireNonNull(name, "name").strip();
        Objects.requireNonNull(type, "type");
        importAliases = List.copyOf(Objects.requireNonNull(importAliases, "importAliases"));
        exportName = Objects.requireNonNull(exportName, "exportName").strip();
        if (exportName.isBlank()) {
            throw new IllegalArgumentException("Export name must not be blank");
        }
        for (String alias : importAliases) {
            if (alias == null || alias.isBlank() || !alias.equals(alias.strip())) {
                throw new IllegalArgumentException("Import aliases must be nonblank and trimmed");
            }
        }
        if (importAliases.stream().distinct().count() != importAliases.size()) {
            throw new IllegalArgumentException("Import aliases must be unique");
        }
        if (maxLength != null && maxLength <= 0) {
            throw new IllegalArgumentException("Max length must be positive");
        }
        if (name.isBlank()) {
            throw new IllegalArgumentException("Field name must not be blank");
        }
    }
}
