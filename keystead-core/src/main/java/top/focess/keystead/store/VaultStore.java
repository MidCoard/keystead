package top.focess.keystead.store;

import top.focess.keystead.model.*;

import java.util.List;
import java.util.Optional;

public interface VaultStore {

    void saveVaultHeader(VaultHeader header);

    Optional<VaultHeader> loadVaultHeader(VaultId vaultId);

    void saveSecretRecord(EncryptedSecretRecord record);

    Optional<EncryptedSecretRecord> loadSecretRecord(VaultId vaultId, SecretId secretId);

    List<SecretMetadata> listMetadata(VaultId vaultId);
}
