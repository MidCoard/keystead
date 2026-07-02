package top.focess.keystead.model;

import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

public record DeletedSecretRecord(
        @NonNull VaultId vaultId,
        @NonNull SecretId secretId,
        @NonNull SecretType secretType,
        long revision,
        @NonNull Instant deletedAt) {

    public DeletedSecretRecord {
        Objects.requireNonNull(vaultId, "vaultId");
        Objects.requireNonNull(secretId, "secretId");
        Objects.requireNonNull(secretType, "secretType");
        Objects.requireNonNull(deletedAt, "deletedAt");
        if (revision < 0) {
            throw new IllegalArgumentException("Record revision must not be negative");
        }
    }
}
