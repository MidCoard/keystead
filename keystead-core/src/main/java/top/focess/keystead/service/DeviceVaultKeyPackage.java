package top.focess.keystead.service;

import java.util.Arrays;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.crypto.CryptoAlgorithmRegistry;
import top.focess.keystead.memory.Wipe;
import top.focess.keystead.model.KeyId;
import top.focess.keystead.model.SecurityLimits;

/**
 * Opaque vault-key material wrapped for one trusted device.
 *
 * <p>Produced by {@link VaultHandle#wrapVaultKeyPackageForDevice} and consumed by {@link
 * VaultService}'s {@code provisionVault} or {@link VaultService#openVaultWithDeviceKey} on the
 * recipient device. The wrapped key bytes are defensively copied on construction and on access, and
 * {@link #toString()} redacts them.
 *
 * @param vaultKeyId the id of the wrapped vault key
 * @param keyAlgorithm the approved device key-package algorithm name
 * @param encryptedVaultKey the device-wrapped vault key bytes
 */
public record DeviceVaultKeyPackage(
        @NonNull KeyId vaultKeyId,
        @NonNull String keyAlgorithm,
        byte @NonNull [] encryptedVaultKey) {

    /** Validates the record components. */
    public DeviceVaultKeyPackage {
        Objects.requireNonNull(vaultKeyId, "vaultKeyId");
        Objects.requireNonNull(keyAlgorithm, "keyAlgorithm");
        Objects.requireNonNull(encryptedVaultKey, "encryptedVaultKey");
        if (!CryptoAlgorithmRegistry.isApprovedDeviceKeyPackage(keyAlgorithm)) {
            throw new IllegalArgumentException("Device key package algorithm is unsupported");
        }
        if (encryptedVaultKey.length == 0) {
            throw new IllegalArgumentException("Encrypted vault key must not be empty");
        }
        if (encryptedVaultKey.length > SecurityLimits.MAX_WRAPPED_KEY_PACKAGE_BYTES) {
            throw new IllegalArgumentException("Encrypted vault key exceeds the size limit");
        }
        encryptedVaultKey = Arrays.copyOf(encryptedVaultKey, encryptedVaultKey.length);
    }

    /** Returns a defensive copy of the encrypted vault key bytes.
     *
     * @return a defensive copy of the encrypted vault key bytes */
    @Override
    public byte @NonNull [] encryptedVaultKey() {
        return Arrays.copyOf(encryptedVaultKey, encryptedVaultKey.length);
    }

    void destroy() {
        Wipe.wipe(encryptedVaultKey);
    }

    @Override
    public @NonNull String toString() {
        return "DeviceVaultKeyPackage[vaultKeyId=%s, keyAlgorithm=%s, encryptedVaultKey=[REDACTED %d bytes]]"
                .formatted(vaultKeyId, keyAlgorithm, encryptedVaultKey.length);
    }
}
