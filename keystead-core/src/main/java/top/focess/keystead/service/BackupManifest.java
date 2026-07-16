package top.focess.keystead.service;

import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.VaultId;

/**
 * Header of a backup archive: format version, vault id, row counts, and creation time.
 *
 * @param formatVersion the backup format version
 * @param vaultId the vault the archive belongs to
 * @param recordCount the number of secret records in the archive
 * @param tombstoneCount the number of tombstones in the archive
 * @param createdAt when the archive was created
 */
public record BackupManifest(
        int formatVersion,
        @NonNull VaultId vaultId,
        int recordCount,
        int tombstoneCount,
        @NonNull Instant createdAt) {

    /** Validates the record components. */
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
