package top.focess.keystead.model;

import java.time.Instant;
import java.util.Objects;
import java.util.Set;
import org.jspecify.annotations.NonNull;

public record SecretMetadata(
        @NonNull SecretId id,
        @NonNull SecretType type,
        @NonNull String title,
        @NonNull SecretClassification classification,
        @NonNull Set<String> tags,
        @NonNull Instant createdAt,
        @NonNull Instant updatedAt,
        long revision) {

    public SecretMetadata {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(title, "title");
        Objects.requireNonNull(classification, "classification");
        Objects.requireNonNull(tags, "tags");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(updatedAt, "updatedAt");
        if (title.isBlank()) {
            throw new IllegalArgumentException("Secret title must not be blank");
        }
        if (revision < 0) {
            throw new IllegalArgumentException("Secret revision must not be negative");
        }
        tags = Set.copyOf(tags);
    }

    public SecretMetadata(
            @NonNull SecretId id,
            @NonNull SecretType type,
            @NonNull String title,
            @NonNull Set<String> tags,
            @NonNull Instant createdAt,
            @NonNull Instant updatedAt,
            long revision) {
        this(id, type, title, SecretClassification.none(), tags, createdAt, updatedAt, revision);
    }
}
