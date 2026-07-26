package top.focess.keystead.store;

import java.util.List;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.crypto.VaultKey;
import top.focess.keystead.model.EncryptedSecretRecord;
import top.focess.keystead.model.VaultHeader;

/**
 * A journaled vault key rotation: the replacement header, the active secret records re-encrypted
 * under the new key, and the next data-encryption key itself. The active records list is defensively
 * copied; the next vault key is held by reference and its ownership transfers to the store on
 * commit.
 *
 * <p>Records no longer carry a vault identifier (the store is vault-scoped), so the v0.2 cross-check
 * against the header's vault id is dropped. The data-encryption key is rewrapped while the passphrase
 * and salt stay fixed, so the vault fingerprint is unchanged across the rotation. Tombstones carry no
 * encrypted payload and are not part of the rotation; the store preserves its existing tombstones.
 *
 * @param header the replacement vault header
 * @param activeRecords the active secret records re-encrypted under the new key
 * @param nextVaultKey the unlocked vault key that the re-encrypted records are encrypted under; its
 *     key id must match {@code header.vaultKeyId()}
 */
public record VaultKeyRotation(
        @NonNull VaultHeader header,
        @NonNull List<EncryptedSecretRecord> activeRecords,
        @NonNull VaultKey nextVaultKey) {

    /** Validates and defensively copies the record components. */
    public VaultKeyRotation {
        Objects.requireNonNull(header, "header");
        activeRecords = List.copyOf(Objects.requireNonNull(activeRecords, "activeRecords"));
        Objects.requireNonNull(nextVaultKey, "nextVaultKey");
        if (!nextVaultKey.keyId().equals(header.vaultKeyId())) {
            throw new IllegalArgumentException(
                    "Next vault key id does not match rotation header vault key id");
        }
    }
}
