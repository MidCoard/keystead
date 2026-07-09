package top.focess.keystead.model;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Predicate;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

public final class SecretTypeSchema {

    private final SecretType type;
    private final List<SecretFieldSchema> fields;
    private final boolean allowsCustomFields;
    private final @Nullable SecretFieldType customFieldType;
    private final boolean customFieldsRevealable;
    private final Map<String, SecretFieldSchema> fieldByName;

    public SecretTypeSchema(
            @NonNull SecretType type,
            @NonNull List<SecretFieldSchema> fields,
            boolean allowsCustomFields) {
        this(
                type,
                fields,
                allowsCustomFields,
                allowsCustomFields ? SecretFieldType.SECRET : null,
                allowsCustomFields);
    }

    public SecretTypeSchema(
            @NonNull SecretType type,
            @NonNull List<SecretFieldSchema> fields,
            boolean allowsCustomFields,
            @Nullable SecretFieldType customFieldType,
            boolean customFieldsRevealable) {
        this.type = Objects.requireNonNull(type, "type");
        this.fields = List.copyOf(Objects.requireNonNull(fields, "fields"));
        this.allowsCustomFields = allowsCustomFields;
        this.customFieldType = customFieldType;
        this.customFieldsRevealable = customFieldsRevealable;
        if (allowsCustomFields && customFieldType == null) {
            throw new IllegalArgumentException("Custom field type is required");
        }
        if (!allowsCustomFields && customFieldType != null) {
            throw new IllegalArgumentException("Custom field type requires custom fields");
        }
        if (!allowsCustomFields && customFieldsRevealable) {
            throw new IllegalArgumentException("Custom fields cannot be revealable when disabled");
        }
        Map<String, SecretFieldSchema> map = new LinkedHashMap<>();
        for (SecretFieldSchema field : this.fields) {
            SecretFieldSchema previous = map.put(field.name(), field);
            if (previous != null) {
                throw new IllegalArgumentException("Duplicate field name: " + field.name());
            }
        }
        this.fieldByName = Collections.unmodifiableMap(map);
    }

    public @NonNull SecretType type() {
        return type;
    }

    public @NonNull List<SecretFieldSchema> fields() {
        return fields;
    }

    public boolean allowsCustomFields() {
        return allowsCustomFields;
    }

    public @Nullable SecretFieldType customFieldType() {
        return customFieldType;
    }

    public boolean customFieldsRevealable() {
        return customFieldsRevealable;
    }

    public @NonNull List<String> fieldNames() {
        return fields.stream().map(SecretFieldSchema::name).toList();
    }

    public @NonNull List<String> requiredFieldNames() {
        return fieldNamesMatching(SecretFieldSchema::required);
    }

    public @NonNull List<String> optionalFieldNames() {
        return fieldNamesMatching(field -> !field.required());
    }

    public @NonNull List<String> secretFieldNames() {
        return fieldNamesMatching(field -> field.type() == SecretFieldType.SECRET);
    }

    public @NonNull List<String> publicFieldNames() {
        return fieldNamesMatching(field -> field.type() == SecretFieldType.TEXT);
    }

    public @NonNull List<String> revealableFieldNames() {
        return fieldNamesMatching(SecretFieldSchema::revealable);
    }

    public @Nullable SecretFieldSchema field(@NonNull String name) {
        Objects.requireNonNull(name, "name");
        return fieldByName.get(name);
    }

    public static @NonNull SecretTypeSchema forType(@NonNull SecretType type) {
        Objects.requireNonNull(type, "type");
        return DEFAULTS.get(type);
    }

    public static @NonNull List<SecretTypeSchema> defaults() {
        return DEFAULT_LIST;
    }

    private @NonNull List<String> fieldNamesMatching(
            @NonNull Predicate<SecretFieldSchema> predicate) {
        Objects.requireNonNull(predicate, "predicate");
        return fields.stream().filter(predicate).map(SecretFieldSchema::name).toList();
    }

    private static final Map<SecretType, SecretTypeSchema> DEFAULTS = buildDefaults();
    private static final List<SecretTypeSchema> DEFAULT_LIST = List.copyOf(DEFAULTS.values());

    private static @NonNull Map<SecretType, SecretTypeSchema> buildDefaults() {
        Map<SecretType, SecretTypeSchema> map = new LinkedHashMap<>();
        map.put(
                SecretType.LOGIN_PASSWORD,
                new SecretTypeSchema(
                        SecretType.LOGIN_PASSWORD,
                        List.of(
                                new SecretFieldSchema(
                                        "username", SecretFieldType.SECRET, true, true),
                                new SecretFieldSchema(
                                        "password", SecretFieldType.SECRET, true, true),
                                new SecretFieldSchema("url", SecretFieldType.TEXT, false, true),
                                new SecretFieldSchema(
                                        "notes", SecretFieldType.SECRET, false, true)),
                        false));
        map.put(
                SecretType.SECURE_NOTE,
                new SecretTypeSchema(
                        SecretType.SECURE_NOTE,
                        List.of(new SecretFieldSchema("body", SecretFieldType.SECRET, true, true)),
                        false));
        map.put(
                SecretType.SSH_KEY,
                new SecretTypeSchema(
                        SecretType.SSH_KEY,
                        List.of(
                                new SecretFieldSchema(
                                        "publicKey", SecretFieldType.TEXT, true, true),
                                new SecretFieldSchema(
                                        "privateKey", SecretFieldType.SECRET, true, true),
                                new SecretFieldSchema(
                                        "passphrase", SecretFieldType.SECRET, false, true)),
                        false));
        map.put(
                SecretType.GPG_KEY,
                new SecretTypeSchema(
                        SecretType.GPG_KEY,
                        List.of(
                                new SecretFieldSchema(
                                        "publicKey", SecretFieldType.TEXT, true, true),
                                new SecretFieldSchema(
                                        "privateKey", SecretFieldType.SECRET, true, true),
                                new SecretFieldSchema(
                                        "passphrase", SecretFieldType.SECRET, false, true)),
                        false));
        map.put(
                SecretType.API_TOKEN,
                new SecretTypeSchema(
                        SecretType.API_TOKEN,
                        List.of(
                                new SecretFieldSchema("token", SecretFieldType.SECRET, true, true),
                                new SecretFieldSchema(
                                        "notes", SecretFieldType.SECRET, false, true)),
                        false));
        map.put(
                SecretType.MFA_SECRET,
                new SecretTypeSchema(
                        SecretType.MFA_SECRET,
                        List.of(
                                new SecretFieldSchema("secret", SecretFieldType.SECRET, true, true),
                                new SecretFieldSchema(
                                        "recoveryCodes", SecretFieldType.SECRET, false, true)),
                        false));
        map.put(
                SecretType.CERTIFICATE,
                new SecretTypeSchema(
                        SecretType.CERTIFICATE,
                        List.of(
                                new SecretFieldSchema(
                                        "certificate", SecretFieldType.TEXT, true, true),
                                new SecretFieldSchema(
                                        "privateKey", SecretFieldType.SECRET, true, true),
                                new SecretFieldSchema(
                                        "passphrase", SecretFieldType.SECRET, false, true)),
                        false));
        map.put(
                SecretType.GENERIC_SECRET,
                new SecretTypeSchema(SecretType.GENERIC_SECRET, List.of(), true));
        return Collections.unmodifiableMap(map);
    }
}
