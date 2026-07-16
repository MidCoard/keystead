package top.focess.keystead.model;

import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

/**
 * A tombstone record marking a secret as deleted: vault id, secret id, type, revision, and
 * deletion timestamp.
 *
 * @param vaultId the vault that contained the secret
 * @param secretId the deleted secret's stable id
 * @param secretType the deleted secret's type
 * @param revision the positive revision at which the secret was deleted
 * @param deletedAt when the secret was deleted
 */
public record DeletedSecretRecord(
        @NonNull VaultId vaultId,
        @NonNull SecretId secretId,
        @NonNull SecretType secretType,
        long revision,
        @NonNull Instant deletedAt) {

    /** Validates the record components. */
    public DeletedSecretRecord {
        Objects.requireNonNull(vaultId, "vaultId");
        Objects.requireNonNull(secretId, "secretId");
        Objects.requireNonNull(secretType, "secretType");
        Objects.requireNonNull(deletedAt, "deletedAt");
        if (revision <= 0) {
            throw new IllegalArgumentException("Record revision must be positive");
        }
    }
}
