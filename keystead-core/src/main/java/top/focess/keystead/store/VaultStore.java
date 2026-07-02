package top.focess.keystead.store;

import java.util.List;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.*;

public interface VaultStore {

    void saveVaultHeader(@NonNull VaultHeader header);

    @NonNull Optional<VaultHeader> loadVaultHeader(@NonNull VaultId vaultId);

    void saveSecretRecord(@NonNull EncryptedSecretRecord record);

    @NonNull Optional<EncryptedSecretRecord> loadSecretRecord(
            @NonNull VaultId vaultId, @NonNull SecretId secretId);

    void deleteSecretRecord(@NonNull VaultId vaultId, @NonNull SecretId secretId);

    @NonNull List<SecretMetadata> listMetadata(@NonNull VaultId vaultId);
}
