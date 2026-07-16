package top.focess.keystead.service;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.DeletedSecretRecord;
import top.focess.keystead.model.EncryptedSecretRecord;
import top.focess.keystead.model.SecretId;
import top.focess.keystead.model.VaultHeader;

/**
 * An encrypted, versioned backup of a vault's header, records, and tombstones. The manifest, header,
 * record list, and tombstone list must all refer to the same vault and agree on counts.
 *
 * @param manifest the archive manifest
 * @param vaultHeader the vault header at backup time
 * @param records the encrypted secret records
 * @param tombstones the encrypted delete tombstones
 */
public record BackupArchive(
        @NonNull BackupManifest manifest,
        @NonNull VaultHeader vaultHeader,
        @NonNull List<EncryptedSecretRecord> records,
        @NonNull List<DeletedSecretRecord> tombstones) {

    /** Validates the record components. */
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
        Set<SecretId> recordIds = recordIds(records);
        requireUniqueRecordIds(records, recordIds);
        for (DeletedSecretRecord tombstone : tombstones) {
            if (!manifest.vaultId().equals(tombstone.vaultId())) {
                throw new ValidationException(
                        "Backup archive contains tombstone from another vault");
            }
        }
        Set<SecretId> tombstoneIds = tombstoneIds(tombstones);
        requireUniqueTombstoneIds(tombstones, tombstoneIds);
        requireDisjointRecordStates(recordIds, tombstoneIds);
    }

    private static @NonNull Set<SecretId> recordIds(@NonNull List<EncryptedSecretRecord> records) {
        return records.stream().map(record -> record.metadata().id()).collect(Collectors.toSet());
    }

    private static @NonNull Set<SecretId> tombstoneIds(
            @NonNull List<DeletedSecretRecord> tombstones) {
        return tombstones.stream().map(DeletedSecretRecord::secretId).collect(Collectors.toSet());
    }

    private static void requireUniqueRecordIds(
            @NonNull List<EncryptedSecretRecord> records, @NonNull Set<SecretId> ids) {
        if (ids.size() != records.size()) {
            throw new ValidationException("Backup archive contains duplicate record primary key");
        }
    }

    private static void requireUniqueTombstoneIds(
            @NonNull List<DeletedSecretRecord> tombstones, @NonNull Set<SecretId> ids) {
        if (ids.size() != tombstones.size()) {
            throw new ValidationException(
                    "Backup archive contains duplicate tombstone primary key");
        }
    }

    private static void requireDisjointRecordStates(
            @NonNull Set<SecretId> recordIds, @NonNull Set<SecretId> tombstoneIds) {
        for (SecretId id : recordIds) {
            if (tombstoneIds.contains(id)) {
                throw new ValidationException(
                        "Backup archive contains active and tombstone rows for primary key");
            }
        }
    }
}
