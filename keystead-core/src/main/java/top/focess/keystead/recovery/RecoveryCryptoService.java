package top.focess.keystead.recovery;

import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.VaultId;
import top.focess.keystead.service.VaultHandle;
import top.focess.keystead.service.VaultService;

/** Client-side cryptographic operations for account and vault recovery. */
public interface RecoveryCryptoService {

    /**
     * Enrolls a new recovery generation, producing a recovery kit, account credential, public key, and
     * encrypted private key.
     *
     * @param enrollmentId the recovery enrollment identifier
     * @param generation the enrollment generation; must be positive
     * @return the enrollment material
     */
    @NonNull RecoveryEnrollmentMaterial enroll(@NonNull String enrollmentId, long generation);

    /**
     * Derives the account credential from a recovery kit.
     *
     * @param kit the recovery kit
     * @return the account credential bytes
     */
    byte @NonNull [] accountCredential(@NonNull RecoveryKit kit);

    /**
     * Wraps a vault's current key for a recovery public key.
     *
     * @param vault the open vault handle
     * @param recoveryKey the recipient recovery public key
     * @param username the account username
     * @param vaultId the vault id
     * @return the recovery vault-key package
     */
    @NonNull RecoveryVaultKeyPackage wrapVaultKey(
            @NonNull VaultHandle vault,
            @NonNull RecoveryPublicKey recoveryKey,
            @NonNull String username,
            @NonNull String vaultId);

    /**
     * Opens a vault from a recovery package using a recovery kit and encrypted private key.
     *
     * @param vaultService the vault service to provision through
     * @param vaultId the vault to open
     * @param keyPackage the recovery vault-key package
     * @param kit the recovery kit
     * @param encryptedPrivateKey the encrypted recovery private key
     * @return an open vault handle
     */
    @NonNull VaultHandle openVault(
            @NonNull VaultService vaultService,
            @NonNull VaultId vaultId,
            @NonNull RecoveryVaultKeyPackage keyPackage,
            @NonNull RecoveryKit kit,
            byte @NonNull [] encryptedPrivateKey);
}
