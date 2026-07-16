package top.focess.keystead.model;

import java.time.Instant;
import java.util.Objects;
import java.util.Set;
import org.jspecify.annotations.NonNull;

/**
 * Non-secret metadata for a stored secret: id, type, profile, timestamps, and revision. Revisions
 * are positive and monotonic within a vault.
 *
 * @param id the secret's stable id
 * @param type the secret type
 * @param profile the non-secret title, classification, tags, and attributes
 * @param createdAt when the secret was first stored
 * @param updatedAt when the secret was last updated
 * @param revision the monotonic revision; must be positive
 */
public record SecretMetadata(
        @NonNull SecretId id,
        @NonNull SecretType type,
        @NonNull SecretProfile profile,
        @NonNull Instant createdAt,
        @NonNull Instant updatedAt,
        long revision) {

    public SecretMetadata {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(profile, "profile");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(updatedAt, "updatedAt");
        if (updatedAt.isBefore(createdAt)) {
            throw new IllegalArgumentException(
                    "Secret updated time must not be before created time");
        }
        if (revision <= 0) {
            throw new IllegalArgumentException("Secret revision must be positive");
        }
    }

    public SecretMetadata(
            @NonNull SecretId id,
            @NonNull SecretType type,
            @NonNull String title,
            @NonNull SecretClassification classification,
            @NonNull Set<String> tags,
            @NonNull Instant createdAt,
            @NonNull Instant updatedAt,
            long revision) {
        this(
                id,
                type,
                new SecretProfile(title, classification, tags),
                createdAt,
                updatedAt,
                revision);
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

    public @NonNull String title() {
        return profile.title();
    }

    public @NonNull SecretClassification classification() {
        return profile.classification();
    }

    public @NonNull Set<String> tags() {
        return profile.tags();
    }
}
