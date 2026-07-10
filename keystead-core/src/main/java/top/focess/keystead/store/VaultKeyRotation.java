package top.focess.keystead.store;

import java.util.List;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.EncryptedSecretRecord;
import top.focess.keystead.model.VaultHeader;

public record VaultKeyRotation(
        @NonNull VaultHeader header, @NonNull List<EncryptedSecretRecord> activeRecords) {

    public VaultKeyRotation {
        Objects.requireNonNull(header, "header");
        activeRecords = List.copyOf(Objects.requireNonNull(activeRecords, "activeRecords"));
        if (activeRecords.stream().anyMatch(record -> !header.vaultId().equals(record.vaultId()))) {
            throw new IllegalArgumentException("Rotation records must belong to the header vault");
        }
    }
}
