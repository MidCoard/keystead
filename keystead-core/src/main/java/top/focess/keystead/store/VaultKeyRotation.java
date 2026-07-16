package top.focess.keystead.store;

import java.util.List;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.EncryptedSecretRecord;
import top.focess.keystead.model.VaultHeader;

/**
 * A journaled vault key rotation: the replacement header and the active secret records re-encrypted
 * under the new key. The active records list is defensively copied.
 *
 * @param header the replacement vault header
 * @param activeRecords the active secret records re-encrypted under the new key
 */
public record VaultKeyRotation(
        @NonNull VaultHeader header, @NonNull List<EncryptedSecretRecord> activeRecords) {

    /** Validates and defensively copies the record components. */
    public VaultKeyRotation {
        Objects.requireNonNull(header, "header");
        activeRecords = List.copyOf(Objects.requireNonNull(activeRecords, "activeRecords"));
        if (activeRecords.stream().anyMatch(record -> !header.vaultId().equals(record.vaultId()))) {
            throw new IllegalArgumentException("Rotation records must belong to the header vault");
        }
    }
}
