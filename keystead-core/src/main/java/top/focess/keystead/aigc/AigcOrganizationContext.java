package top.focess.keystead.aigc;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Collectors;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.model.EncryptedSecretRecord;
import top.focess.keystead.model.SecretClassification;
import top.focess.keystead.model.SecretId;
import top.focess.keystead.model.SecretMetadata;
import top.focess.keystead.model.SecretType;

/**
 * Non-secret, derived view of a secret's organization metadata, suitable for feeding to an
 * AI-generation context without exposing secret payloads.
 *
 * @param secretId the secret's stable id
 * @param secretType the secret type
 * @param title the trimmed secret title
 * @param classification the secret classification
 * @param tags the secret's tag set
 * @param attributes the secret's custom attributes
 * @param revision the secret revision; must be positive
 */
public record AigcOrganizationContext(
        @NonNull SecretId secretId,
        @NonNull SecretType secretType,
        @NonNull String title,
        @NonNull SecretClassification classification,
        @NonNull Set<String> tags,
        @NonNull Map<String, String> attributes,
        long revision) {

    /** Validates and copies the record components. */
    public AigcOrganizationContext {
        Objects.requireNonNull(secretId, "secretId");
        Objects.requireNonNull(secretType, "secretType");
        title = Objects.requireNonNull(title, "title").trim();
        classification = Objects.requireNonNull(classification, "classification");
        tags = Set.copyOf(Objects.requireNonNull(tags, "tags"));
        attributes = Map.copyOf(Objects.requireNonNull(attributes, "attributes"));
        if (title.isBlank()) {
            throw new IllegalArgumentException("AIGC context title must not be blank");
        }
        if (revision <= 0) {
            throw new IllegalArgumentException("AIGC context revision must be positive");
        }
    }

    /**
     * Derives a context from an encrypted secret record's metadata.
     *
     * @param record the source record
     * @return the derived context
     */
    public static @NonNull AigcOrganizationContext from(@NonNull EncryptedSecretRecord record) {
        Objects.requireNonNull(record, "record");
        return from(record.metadata());
    }

    /**
     * Derives a context from secret metadata.
     *
     * @param metadata the source metadata
     * @return the derived context
     */
    public static @NonNull AigcOrganizationContext from(@NonNull SecretMetadata metadata) {
        Objects.requireNonNull(metadata, "metadata");
        return new AigcOrganizationContext(
                metadata.id(),
                metadata.type(),
                metadata.title(),
                metadata.classification(),
                metadata.tags(),
                metadata.profile().attributes(),
                metadata.revision());
    }

    /** Returns the context as an unmodifiable map of non-secret prompt fields.
     *
     * @return the prompt field map */
    public @NonNull Map<String, String> promptFields() {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("secretId", secretId.value().toString());
        fields.put("secretType", secretType.name());
        fields.put("title", title);
        putNullable(fields, "category", classification.category());
        putNullable(fields, "provider", classification.provider());
        putNullable(fields, "software", classification.software());
        putNullable(fields, "account", classification.account());
        fields.put("labels", sortedValues(classification.labels()));
        fields.put("tags", sortedValues(tags));
        new TreeMap<>(attributes).forEach((key, value) -> fields.put("attribute." + key, value));
        fields.put("revision", Long.toString(revision));
        return Collections.unmodifiableMap(new LinkedHashMap<>(fields));
    }

    /** Returns the context as newline-joined {@code key=value} prompt text.
     *
     * @return the prompt text */
    public @NonNull String toPromptText() {
        return promptFields().entrySet().stream()
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .collect(Collectors.joining("\n"));
    }

    private static void putNullable(
            @NonNull Map<String, String> fields, @NonNull String key, @Nullable String value) {
        if (value != null) {
            fields.put(key, value);
        }
    }

    private static @NonNull String sortedValues(@NonNull Set<String> values) {
        return new TreeSet<>(values).stream().collect(Collectors.joining(","));
    }
}
