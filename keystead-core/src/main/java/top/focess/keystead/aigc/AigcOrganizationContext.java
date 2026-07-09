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

public record AigcOrganizationContext(
        @NonNull SecretId secretId,
        @NonNull SecretType secretType,
        @NonNull String title,
        @NonNull SecretClassification classification,
        @NonNull Set<String> tags,
        @NonNull Map<String, String> attributes,
        long revision) {

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

    public static @NonNull AigcOrganizationContext from(@NonNull EncryptedSecretRecord record) {
        Objects.requireNonNull(record, "record");
        return from(record.metadata());
    }

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
