package top.focess.keystead.recovery;

import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.VaultId;
import top.focess.keystead.service.VaultHandle;
import top.focess.keystead.service.VaultService;

/** Client-side cryptographic operations for account and vault recovery. */
public interface RecoveryCryptoService {

    @NonNull RecoveryEnrollmentMaterial enroll(@NonNull String enrollmentId, long generation);

    byte @NonNull [] accountCredential(@NonNull RecoveryKit kit);

    @NonNull RecoveryVaultKeyPackage wrapVaultKey(
            @NonNull VaultHandle vault,
            @NonNull RecoveryPublicKey recoveryKey,
            @NonNull String username,
            @NonNull String vaultId);

    @NonNull VaultHandle openVault(
            @NonNull VaultService vaultService,
            @NonNull VaultId vaultId,
            @NonNull RecoveryVaultKeyPackage keyPackage,
            @NonNull RecoveryKit kit,
            byte @NonNull [] encryptedPrivateKey);
}
