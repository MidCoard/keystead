package top.focess.keystead.service;

import java.util.Objects;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.SecretFieldSchema;
import top.focess.keystead.model.SecretTypeSchema;

/** Validates structured-secret field names against a secret-type schema. */
public final class SecretTypeSchemaValidator {

    /**
     * Validates that the supplied field names are non-blank, satisfy every required field in the
     * schema, and do not introduce unknown fields when custom fields are disallowed.
     *
     * @param schema the secret-type schema defining required and allowed fields
     * @param fieldNames the field names to validate
     * @throws ValidationException if a field name is blank, a required field is missing, or an
     *     unknown field is present while custom fields are disallowed
     */
    public static void validate(@NonNull SecretTypeSchema schema, @NonNull Set<String> fieldNames) {
        Objects.requireNonNull(schema, "schema");
        Objects.requireNonNull(fieldNames, "fieldNames");
        for (String name : fieldNames) {
            if (name == null || name.isBlank()) {
                throw new ValidationException("Secret field name must not be blank");
            }
        }
        for (SecretFieldSchema field : schema.fields()) {
            if (field.required() && !fieldNames.contains(field.name())) {
                throw new ValidationException(
                        "Missing required field for " + schema.type() + ": " + field.name());
            }
        }
        if (!schema.allowsCustomFields()) {
            for (String name : fieldNames) {
                if (schema.field(name) == null) {
                    throw new ValidationException(
                            "Unknown field for " + schema.type() + ": " + name);
                }
            }
        }
    }

    private SecretTypeSchemaValidator() {}
}
