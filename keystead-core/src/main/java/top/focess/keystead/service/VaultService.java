package top.focess.keystead.service;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.model.KeyId;
import top.focess.keystead.model.VaultId;

/**
 * Entry point for creating, opening, provisioning, and rotating vaults.
 *
 * <p>A vault is a set of encrypted secret records persisted by a {@link
 * top.focess.keystead.store.VaultStore}. The service derives and wraps a random vault key from a
 * master password, or unwraps one from a device-wrapped package, and returns a live {@link
 * VaultHandle} that holds the unlocked key only for the lifetime of the handle. Closing the handle
 * destroys its key material.
 *
 * <p>The caller owns every {@code char[]} and {@code byte[]} passed to this service. Master
 * passwords, device private keys, and context buffers must be wiped by the caller once the call
 * returns; the service copies what it needs and wipes its own transient copies, but it cannot
 * reach arrays it does not own.
 */
public interface VaultService {

    /**
     * Creates a new password-protected vault and returns a handle holding its unlocked key.
     *
     * <p>The {@code masterPassword} derives a wrapping key with the configured KDF parameters; the
     * derived key wraps a freshly generated random vault key and is not used directly as the
     * record-encryption key. The vault header is persisted before the handle is returned.
     *
     * @param request the vault id and creation parameters
     * @param masterPassword caller-owned master password; wiped by the caller, not by this service
     * @return a live handle owning the new vault key
     * @throws ValidationException if the vault already exists or the request is invalid
     */
    @NonNull VaultHandle createVault(
            @NonNull CreateVaultRequest request, char @NonNull [] masterPassword);

    /**
     * Opens an existing password-protected vault and returns a handle holding its unlocked key.
     *
     * @param vaultId the vault to open
     * @param masterPassword caller-owned master password; wiped by the caller
     * @return a live handle owning the unwrapped vault key
     * @throws ValidationException if the vault does not exist or is not protected by a master
     *     password header
     * @throws top.focess.keystead.crypto.CryptoException if the password is wrong or the header is
     *     corrupt
     */
    @NonNull VaultHandle openVault(@NonNull VaultId vaultId, char @NonNull [] masterPassword);

    /**
     * Rotates the vault key and re-encrypts every current record under the new key.
     *
     * <p>The new key is wrapped with the same KDF parameters and master password, and the header,
     * re-encrypted records, and tombstones are committed as one atomic store mutation. On failure
     * the previous key and records are left untouched.
     *
     * @param vaultId the vault whose key should be rotated
     * @param masterPassword caller-owned master password; wiped by the caller
     * @return a live handle owning the new vault key
     * @throws ValidationException if the vault does not exist
     * @throws top.focess.keystead.crypto.CryptoException if the password is wrong
     */
    @NonNull VaultHandle rotateVaultKey(@NonNull VaultId vaultId, char @NonNull [] masterPassword);

    /**
     * Provisions a vault on this device from a device-wrapped vault-key package.
     *
     * <p>Used when a vault was created on another device and its key was wrapped for this device's
     * public key. The vault header is written from the package; no master password is involved.
     *
     * @param vaultId the vault to provision
     * @param encryptedVaultKey the device-wrapped vault key produced by {@link
     *     VaultHandle#wrapVaultKeyForDevice}
     * @param devicePrivateKey caller-owned device private key; wiped by the caller
     * @param context caller-owned binding context used when the key was wrapped; wiped by the caller
     * @return a live handle owning the unwrapped vault key
     * @throws ValidationException if the package cannot be unwrapped for this device
     */
    @NonNull VaultHandle provisionVault(
            @NonNull VaultId vaultId,
            byte @NonNull [] encryptedVaultKey,
            byte @NonNull [] devicePrivateKey,
            byte @NonNull [] context);

    /**
     * Provisions a vault from a typed {@link DeviceVaultKeyPackage} carrying the wrapped key and its
     * algorithm. See the byte-array overload of this method.
     *
     * @param vaultId the vault to provision
     * @param keyPackage the device-wrapped vault key package
     * @param devicePrivateKey caller-owned device private key; wiped by the caller
     * @param context caller-owned binding context used when the key was wrapped; wiped by the caller
     * @return a live handle owning the unwrapped vault key
     * @throws ValidationException if the package cannot be unwrapped for this device
     */
    @NonNull VaultHandle provisionVault(
            @NonNull VaultId vaultId,
            @NonNull DeviceVaultKeyPackage keyPackage,
            byte @NonNull [] devicePrivateKey,
            byte @NonNull [] context);

    /**
     * Provisions a vault from explicit package metadata. The caller retains ownership of every
     * supplied array.
     *
     * @param vaultId the vault to provision
     * @param vaultKeyId the public identifier of the wrapped vault key
     * @param keyAlgorithm the device key algorithm used to wrap the vault key
     * @param encryptedVaultKey the wrapped vault key bytes
     * @param devicePrivateKey caller-owned device private key; wiped by the caller
     * @param context caller-owned binding context used when the key was wrapped; wiped by the caller
     * @return a live handle owning the unwrapped vault key
     * @throws ValidationException if the package cannot be unwrapped for this device
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

    /**
     * Opens a device-provisioned vault with its device private key, without a master password.
     *
     * @param vaultId the vault to open
     * @param devicePrivateKey caller-owned device private key; wiped by the caller
     * @param context caller-owned binding context used when the key was wrapped; wiped by the caller
     * @return a live handle owning the unwrapped vault key
     * @throws ValidationException if the vault does not exist or is not protected by a device key
     *     package
     */
    @NonNull VaultHandle openVaultWithDeviceKey(
            @NonNull VaultId vaultId, byte @NonNull [] devicePrivateKey, byte @NonNull [] context);
}
