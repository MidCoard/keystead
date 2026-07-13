package top.focess.keystead.recovery;

import java.util.Arrays;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.crypto.CryptoAlgorithmRegistry;
import top.focess.keystead.model.KeyId;

/** Opaque vault-key package encrypted to a recovery enrollment. */
public record RecoveryVaultKeyPackage(
        @NonNull String username,
        @NonNull String vaultId,
        @NonNull KeyId vaultKeyId,
        @NonNull String enrollmentId,
        long generation,
        @NonNull String keyAlgorithm,
        byte @NonNull [] encryptedVaultKey) {

    private static final int MAX_CIPHERTEXT_BYTES = 1024 * 1024;

    public RecoveryVaultKeyPackage {
        username = requireNotBlank(username, "username");
        vaultId = requireNotBlank(vaultId, "vaultId");
        Objects.requireNonNull(vaultKeyId, "vaultKeyId");
        enrollmentId = RecoveryKit.requireIdentifier(enrollmentId);
        if (generation <= 0) {
            throw new IllegalArgumentException("Recovery generation must be positive");
        }
        Objects.requireNonNull(keyAlgorithm, "keyAlgorithm");
        if (!CryptoAlgorithmRegistry.isApprovedDeviceKeyPackage(keyAlgorithm)) {
            throw new IllegalArgumentException("Recovery package algorithm is unsupported");
        }
        Objects.requireNonNull(encryptedVaultKey, "encryptedVaultKey");
        if (encryptedVaultKey.length == 0 || encryptedVaultKey.length > MAX_CIPHERTEXT_BYTES) {
            throw new IllegalArgumentException("Encrypted recovery vault key is invalid");
        }
        encryptedVaultKey = Arrays.copyOf(encryptedVaultKey, encryptedVaultKey.length);
    }

    @Override
    public byte @NonNull [] encryptedVaultKey() {
        return Arrays.copyOf(encryptedVaultKey, encryptedVaultKey.length);
    }

    @Override
    public @NonNull String toString() {
        return "RecoveryVaultKeyPackage[username=%s, vaultId=%s, vaultKeyId=%s, enrollmentId=%s, generation=%d, keyAlgorithm=%s, encryptedVaultKey=[REDACTED %d bytes]]"
                .formatted(
                        username,
                        vaultId,
                        vaultKeyId,
                        enrollmentId,
                        generation,
                        keyAlgorithm,
                        encryptedVaultKey.length);
    }

    private static @NonNull String requireNotBlank(@NonNull String value, @NonNull String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank() || value.length() > 255) {
            throw new IllegalArgumentException(field + " is invalid");
        }
        return value;
    }
}
