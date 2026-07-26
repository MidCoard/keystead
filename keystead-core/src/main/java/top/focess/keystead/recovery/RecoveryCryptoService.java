package top.focess.keystead.recovery;

import java.nio.file.Path;
import org.jspecify.annotations.NonNull;
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
     * <p>The vault fingerprint (from the open handle) is bound into the wrapping context and stored in
     * the package; no vault id is used.
     *
     * @param vault the open vault handle
     * @param recoveryKey the recipient recovery public key
     * @param username the account username
     * @return the recovery vault-key package
     */
    @NonNull RecoveryVaultKeyPackage wrapVaultKey(
            @NonNull VaultHandle vault,
            @NonNull RecoveryPublicKey recoveryKey,
            @NonNull String username);

    /**
     * Provisions a new vault file from a recovery package using a recovery kit and encrypted private
     * key.
     *
     * <p>The recovery private key is decrypted from the kit, the vault key is unwrapped from the
     * package, and a new single-file vault is provisioned at {@code file} with a recovery slot. The
     * provisioned vault starts empty and is filled by syncing records from the server.
     *
     * @param vaultService the vault service to provision through
     * @param file the vault file to create; must not already exist as a vault
     * @param keyPackage the recovery vault-key package
     * @param kit the recovery kit
     * @param encryptedPrivateKey the encrypted recovery private key
     * @return an open vault handle
     */
    @NonNull VaultHandle openVault(
            @NonNull VaultService vaultService,
            @NonNull Path file,
            @NonNull RecoveryVaultKeyPackage keyPackage,
            @NonNull RecoveryKit kit,
            byte @NonNull [] encryptedPrivateKey);
}
