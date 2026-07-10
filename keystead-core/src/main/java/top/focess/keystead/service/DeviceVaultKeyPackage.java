package top.focess.keystead.service;

import java.util.Arrays;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.crypto.CryptoAlgorithmRegistry;
import top.focess.keystead.model.KeyId;

/** Opaque vault-key material wrapped for one trusted device. */
public record DeviceVaultKeyPackage(
        @NonNull KeyId vaultKeyId,
        @NonNull String keyAlgorithm,
        byte @NonNull [] encryptedVaultKey) {

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
        encryptedVaultKey = Arrays.copyOf(encryptedVaultKey, encryptedVaultKey.length);
    }

    @Override
    public byte @NonNull [] encryptedVaultKey() {
        return Arrays.copyOf(encryptedVaultKey, encryptedVaultKey.length);
    }

    @Override
    public @NonNull String toString() {
        return "DeviceVaultKeyPackage[vaultKeyId=%s, keyAlgorithm=%s, encryptedVaultKey=[REDACTED %d bytes]]"
                .formatted(vaultKeyId, keyAlgorithm, encryptedVaultKey.length);
    }
}
