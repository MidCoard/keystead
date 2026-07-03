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
    }
}
