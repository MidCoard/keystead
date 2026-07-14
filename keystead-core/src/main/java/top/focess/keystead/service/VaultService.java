package top.focess.keystead.service;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.model.KeyId;
import top.focess.keystead.model.VaultId;

public interface VaultService {

    @NonNull VaultHandle createVault(
            @NonNull CreateVaultRequest request, char @NonNull [] masterPassword);

    @NonNull VaultHandle openVault(@NonNull VaultId vaultId, char @NonNull [] masterPassword);

    @NonNull VaultHandle rotateVaultKey(@NonNull VaultId vaultId, char @NonNull [] masterPassword);

    @NonNull VaultHandle provisionVault(
            @NonNull VaultId vaultId,
            byte @NonNull [] encryptedVaultKey,
            byte @NonNull [] devicePrivateKey,
            byte @NonNull [] context);

    @NonNull VaultHandle provisionVault(
            @NonNull VaultId vaultId,
            @NonNull DeviceVaultKeyPackage keyPackage,
            byte @NonNull [] devicePrivateKey,
            byte @NonNull [] context);

    /**
     * Provisions a vault from explicit package metadata. The caller retains ownership of every
     * supplied array.
     */
    default @NonNull VaultHandle provisionVault(
            @NonNull VaultId vaultId,
            @NonNull KeyId vaultKeyId,
            @NonNull String keyAlgorithm,
            byte @NonNull [] encryptedVaultKey,
            byte @NonNull [] devicePrivateKey,
            byte @NonNull [] context) {
        @Nullable DeviceVaultKeyPackage keyPackage = null;
        try {
            keyPackage = new DeviceVaultKeyPackage(vaultKeyId, keyAlgorithm, encryptedVaultKey);
            return provisionVault(vaultId, keyPackage, devicePrivateKey, context);
        } finally {
            if (keyPackage != null) {
                keyPackage.destroy();
            }
        }
    }

    @NonNull VaultHandle openVaultWithDeviceKey(
            @NonNull VaultId vaultId, byte @NonNull [] devicePrivateKey, byte @NonNull [] context);
}
