package top.focess.keystead.model;

import java.util.List;
import java.util.Locale;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

public record SecretTypeCatalogEntry(
        @NonNull SecretTypeSchema schema,
        @Nullable String defaultCategory,
        @Nullable String defaultProvider,
        @Nullable String defaultSoftware,
        @Nullable SecretFieldType customFieldType) {

    public SecretTypeCatalogEntry {
        schema = Objects.requireNonNull(schema, "schema");
        defaultCategory = normalizeTaxonomy(defaultCategory);
        defaultProvider = normalizeTaxonomy(defaultProvider);
        defaultSoftware = normalizeTaxonomy(defaultSoftware);
        if (schema.allowsCustomFields() && customFieldType == null) {
            throw new IllegalArgumentException("Custom field type is required");
        }
        if (!schema.allowsCustomFields() && customFieldType != null) {
            throw new IllegalArgumentException("Custom field type requires custom fields");
        }
    }

    public @NonNull SecretType type() {
        return schema.type();
    }

    public @NonNull List<SecretFieldSchema> fields() {
        return schema.fields();
    }

    public @NonNull List<String> fieldNames() {
        return schema.fieldNames();
    }

    public boolean allowsCustomFields() {
        return schema.allowsCustomFields();
    }

    public boolean customFieldsRevealable() {
        return schema.customFieldsRevealable();
    }

    private static @Nullable String normalizeTaxonomy(@Nullable String value) {
        if (value == null) {
            return null;
        }
        String normalized = value.trim();
        return normalized.isBlank() ? null : normalized.toLowerCase(Locale.ROOT);
    }
}
