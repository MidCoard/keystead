package top.focess.keystead.service;

import java.util.Objects;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.SecretFieldSchema;
import top.focess.keystead.model.SecretTypeSchema;

public final class SecretTypeSchemaValidator {

    private SecretTypeSchemaValidator() {}

    public static void validate(@NonNull SecretTypeSchema schema, @NonNull Set<String> fieldNames) {
        Objects.requireNonNull(schema, "schema");
        Objects.requireNonNull(fieldNames, "fieldNames");
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
}
