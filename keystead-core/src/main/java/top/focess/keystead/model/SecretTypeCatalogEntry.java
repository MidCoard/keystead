package top.focess.keystead.model;

import java.util.List;
import java.util.Locale;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * A catalog entry pairing a secret type schema with default taxonomy values. Taxonomy defaults are
 * trimmed and lowercased; blank values become {@code null}.
 *
 * @param schema the secret type schema
 * @param defaultCategory the optional default category
 * @param defaultProvider the optional default provider
 * @param defaultSoftware the optional default software
 * @param customFieldType the field type for custom fields, or {@code null} when custom fields are
 *     not allowed
 */
public record SecretTypeCatalogEntry(
        @NonNull SecretTypeSchema schema,
        @Nullable String defaultCategory,
        @Nullable String defaultProvider,
        @Nullable String defaultSoftware,
        @Nullable SecretFieldType customFieldType) {

    /** Validates and normalizes the record components. */
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

    /** Returns the secret type.
     *
     * @return the secret type */
    public @NonNull SecretType type() {
        return schema.type();
    }

    /** Returns the field schemas.
     *
     * @return the field schemas */
    public @NonNull List<SecretFieldSchema> fields() {
        return schema.fields();
    }

    /** Returns the ordered field names.
     *
     * @return the ordered field names */
    public @NonNull List<String> fieldNames() {
        return schema.fieldNames();
    }

    /** Returns whether custom fields are allowed.
     *
     * @return {@code true} if custom fields are allowed */
    public boolean allowsCustomFields() {
        return schema.allowsCustomFields();
    }

    /** Returns whether custom fields are revealable.
     *
     * @return {@code true} if custom fields are revealable */
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
