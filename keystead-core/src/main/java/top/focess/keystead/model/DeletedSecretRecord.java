package top.focess.keystead.model;

import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

/**
 * A tombstone record marking a secret as deleted: secret id, type, revision, and deletion
 * timestamp. As with {@link EncryptedSecretRecord}, no vault identifier is stored; the owning
 * handle carries the {@link VaultFingerprint}.
 *
 * @param secretId the deleted secret's stable id
 * @param secretType the deleted secret's type
 * @param revision the positive revision at which the secret was deleted
 * @param deletedAt when the secret was deleted
 */
public record DeletedSecretRecord(
        @NonNull SecretId secretId,
        @NonNull SecretType secretType,
        long revision,
        @NonNull Instant deletedAt) {

    /** Validates the record components. */
    public DeletedSecretRecord {
        Objects.requireNonNull(secretId, "secretId");
        Objects.requireNonNull(secretType, "secretType");
        Objects.requireNonNull(deletedAt, "deletedAt");
        if (revision <= 0) {
            throw new IllegalArgumentException("Record revision must be positive");
        }
    }
}
