package top.focess.keystead.store;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.*;

public interface VaultStore {

    void saveVaultHeader(@NonNull VaultHeader header);

    @NonNull Optional<VaultHeader> loadVaultHeader(@NonNull VaultId vaultId);

    long nextRevision(@NonNull VaultId vaultId);

    void recordRevision(@NonNull VaultId vaultId, long revision);

    default void commitMutation(@NonNull VaultId vaultId, @NonNull VaultMutation mutation) {
        Objects.requireNonNull(vaultId, "vaultId");
        Objects.requireNonNull(mutation, "mutation");
        synchronized (this) {
            mutation.commit(nextRevision(vaultId));
        }
    }

    default void commitVaultKeyRotation(@NonNull VaultKeyRotation rotation) {
        throw new UnsupportedOperationException("Vault key rotation is not supported by this store");
    }

    void saveSecretRecord(@NonNull EncryptedSecretRecord record);

    @NonNull Optional<EncryptedSecretRecord> loadSecretRecord(
            @NonNull VaultId vaultId, @NonNull SecretId secretId);

    void deleteSecretRecord(@NonNull VaultId vaultId, @NonNull SecretId secretId);

    void saveDeletedSecretRecord(@NonNull DeletedSecretRecord record);

    @NonNull Optional<DeletedSecretRecord> loadDeletedSecretRecord(
            @NonNull VaultId vaultId, @NonNull SecretId secretId);

    void deleteDeletedSecretRecord(@NonNull VaultId vaultId, @NonNull SecretId secretId);

    @NonNull List<SecretMetadata> listMetadata(@NonNull VaultId vaultId);

    @NonNull List<EncryptedSecretRecord> listSecretRecords(@NonNull VaultId vaultId);

    @NonNull List<DeletedSecretRecord> listDeletedSecretRecords(@NonNull VaultId vaultId);
}
