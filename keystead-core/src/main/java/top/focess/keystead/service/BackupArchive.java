package top.focess.keystead.service;

import java.util.List;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.DeletedSecretRecord;
import top.focess.keystead.model.EncryptedSecretRecord;
import top.focess.keystead.model.VaultHeader;

public record BackupArchive(
        @NonNull BackupManifest manifest,
        @NonNull VaultHeader vaultHeader,
        @NonNull List<EncryptedSecretRecord> records,
        @NonNull List<DeletedSecretRecord> tombstones) {

    public BackupArchive {
        Objects.requireNonNull(manifest, "manifest");
        Objects.requireNonNull(vaultHeader, "vaultHeader");
        records = List.copyOf(Objects.requireNonNull(records, "records"));
        tombstones = List.copyOf(Objects.requireNonNull(tombstones, "tombstones"));
        if (manifest.formatVersion() != VaultBackupService.FORMAT_VERSION) {
            throw new ValidationException(
                    "Backup archive format version is unsupported: " + manifest.formatVersion());
        }
        if (!manifest.vaultId().equals(vaultHeader.vaultId())) {
            throw new ValidationException("Backup archive vault header does not match manifest");
        }
        if (manifest.recordCount() != records.size()) {
            throw new ValidationException("Backup archive record count does not match manifest");
        }
        if (manifest.tombstoneCount() != tombstones.size()) {
            throw new ValidationException("Backup archive tombstone count does not match manifest");
        }
        for (EncryptedSecretRecord record : records) {
            if (!manifest.vaultId().equals(record.vaultId())) {
                throw new ValidationException("Backup archive contains record from another vault");
            }
        }
        for (DeletedSecretRecord tombstone : tombstones) {
            if (!manifest.vaultId().equals(tombstone.vaultId())) {
                throw new ValidationException(
                        "Backup archive contains tombstone from another vault");
            }
        }
    }
}
