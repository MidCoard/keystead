package top.focess.keystead.service;

import java.io.InputStream;
import java.io.OutputStream;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.DeletedSecretRecord;
import top.focess.keystead.model.EncryptedSecretRecord;
import top.focess.keystead.model.VaultHeader;
import top.focess.keystead.model.VaultId;
import top.focess.keystead.store.VaultStore;

public final class VaultBackupService {

    public static final int FORMAT_VERSION = 1;

    private final Clock clock;

    public VaultBackupService() {
        this(Clock.systemUTC());
    }

    public VaultBackupService(@NonNull Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public @NonNull BackupArchive export(@NonNull VaultStore store, @NonNull VaultId vaultId) {
        Objects.requireNonNull(store, "store");
        Objects.requireNonNull(vaultId, "vaultId");
        VaultHeader header =
                store.loadVaultHeader(vaultId)
                        .orElseThrow(
                                () ->
                                        new ValidationException(
                                                "Vault not found for backup: " + vaultId));
        List<EncryptedSecretRecord> records = store.listSecretRecords(vaultId);
        List<DeletedSecretRecord> tombstones = store.listDeletedSecretRecords(vaultId);
        BackupManifest manifest =
                new BackupManifest(
                        FORMAT_VERSION,
                        vaultId,
                        records.size(),
                        tombstones.size(),
                        clock.instant());
        return new BackupArchive(manifest, header, records, tombstones);
    }

    public @NonNull BackupImportReport restore(
            @NonNull VaultStore target, @NonNull BackupArchive archive) {
        return restore(target, archive, 0);
    }

    public @NonNull BackupImportReport restore(
            @NonNull VaultStore target, @NonNull BackupReadResult readResult) {
        Objects.requireNonNull(readResult, "readResult");
        return restore(target, readResult.archive(), readResult.unsupported());
    }

    private @NonNull BackupImportReport restore(
            @NonNull VaultStore target, @NonNull BackupArchive archive, int unsupported) {
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(archive, "archive");
        Optional<VaultHeader> existingHeader = target.loadVaultHeader(archive.manifest().vaultId());
        if (existingHeader.isPresent()
                && !existingHeader.get().equals(archive.vaultHeader())) {
            throw new ValidationException(
                    "Backup restore would overwrite a different local vault header");
        }
        target.saveVaultHeader(archive.vaultHeader());
        int imported = 0;
        int skipped = 0;
        List<BackupConflict> conflicts = new ArrayList<>();
        for (EncryptedSecretRecord record : archive.records()) {
            Optional<EncryptedSecretRecord> existing =
                    target.loadSecretRecord(record.vaultId(), record.metadata().id());
            if (existing.isPresent() && existing.get().revision() >= record.revision()) {
                skipped++;
                conflicts.add(
                        new BackupConflict(
                                record.metadata().id(),
                                existing.get().revision(),
                                record.revision()));
                continue;
            }
            Optional<DeletedSecretRecord> deleted =
                    target.loadDeletedSecretRecord(record.vaultId(), record.metadata().id());
            if (deleted.isPresent() && deleted.get().revision() >= record.revision()) {
                skipped++;
                conflicts.add(
                        new BackupConflict(
                                record.metadata().id(),
                                deleted.get().revision(),
                                record.revision()));
                continue;
            }
            target.saveSecretRecord(record);
            imported++;
        }
        int tombstones = 0;
        for (DeletedSecretRecord tombstone : archive.tombstones()) {
            Optional<EncryptedSecretRecord> existing =
                    target.loadSecretRecord(tombstone.vaultId(), tombstone.secretId());
            if (existing.isPresent() && existing.get().revision() >= tombstone.revision()) {
                skipped++;
                conflicts.add(
                        new BackupConflict(
                                tombstone.secretId(),
                                existing.get().revision(),
                                tombstone.revision()));
                continue;
            }
            Optional<DeletedSecretRecord> deleted =
                    target.loadDeletedSecretRecord(tombstone.vaultId(), tombstone.secretId());
            if (deleted.isPresent() && deleted.get().revision() >= tombstone.revision()) {
                skipped++;
                conflicts.add(
                        new BackupConflict(
                                tombstone.secretId(),
                                deleted.get().revision(),
                                tombstone.revision()));
                continue;
            }
            target.saveDeletedSecretRecord(tombstone);
            tombstones++;
        }
        return new BackupImportReport(imported, skipped, unsupported, tombstones, conflicts);
    }

    public void writeTo(@NonNull BackupArchive archive, @NonNull OutputStream output) {
        BackupArchiveCodec.write(archive, output);
    }

    public @NonNull BackupReadResult readFrom(@NonNull InputStream input) {
        return BackupArchiveCodec.read(input);
    }
}
