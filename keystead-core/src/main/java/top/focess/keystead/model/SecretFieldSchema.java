package top.focess.keystead.model;

import java.util.List;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Schema for a single secret field: name, type, required/revealable flags, import aliases, export
 * name, and optional max length.
 *
 * @param name the non-blank, stripped field name
 * @param type the field sensitivity type
 * @param required whether the field must be present
 * @param revealable whether the field value may be revealed after decryption
 * @param importAliases alternate names recognised when importing
 * @param exportName the non-blank, stripped name used when exporting
 * @param maxLength the optional maximum value length, or {@code null} for no limit
 */
public record SecretFieldSchema(
        @NonNull String name,
        @NonNull SecretFieldType type,
        boolean required,
        boolean revealable,
        @NonNull List<String> importAliases,
        @NonNull String exportName,
        @Nullable Integer maxLength) {

    /**
     * Constructs a field schema with no import aliases, the field name as the export name, and no
     * max length.
     *
     * @param name the non-blank, stripped field name
     * @param type the field sensitivity type
     * @param required whether the field must be present
     * @param revealable whether the field value may be revealed after decryption
     */
    public SecretFieldSchema(
            @NonNull String name,
            @NonNull SecretFieldType type,
            boolean required,
            boolean revealable) {
        this(name, type, required, revealable, List.of(), name, null);
    }

    /** Validates and normalizes the record components. */
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
