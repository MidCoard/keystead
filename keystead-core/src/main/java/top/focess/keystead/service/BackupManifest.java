package top.focess.keystead.service;

import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.VaultId;

public record BackupManifest(
        int formatVersion,
        @NonNull VaultId vaultId,
        int recordCount,
        int tombstoneCount,
        @NonNull Instant createdAt) {

    public BackupManifest {
        Objects.requireNonNull(vaultId, "vaultId");
        Objects.requireNonNull(createdAt, "createdAt");
        if (formatVersion <= 0) {
            throw new IllegalArgumentException("Backup format version must be positive");
        }
        if (recordCount < 0 || tombstoneCount < 0) {
            throw new IllegalArgumentException("Backup counts must not be negative");
        }
    }
}
