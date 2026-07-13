package top.focess.keystead.recovery;

import java.util.Arrays;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.crypto.CryptoAlgorithmRegistry;

/** Public wrapping key associated with one recovery enrollment generation. */
public record RecoveryPublicKey(
        @NonNull String enrollmentId,
        long generation,
        @NonNull String keyAlgorithm,
        byte @NonNull [] publicKey) {

    private static final int MAX_PUBLIC_KEY_BYTES = 64 * 1024;

    public RecoveryPublicKey {
        enrollmentId = RecoveryKit.requireIdentifier(enrollmentId);
        if (generation <= 0) {
            throw new IllegalArgumentException("Recovery generation must be positive");
        }
        Objects.requireNonNull(keyAlgorithm, "keyAlgorithm");
        if (!CryptoAlgorithmRegistry.isApprovedDeviceKeyPackage(keyAlgorithm)) {
            throw new IllegalArgumentException("Recovery public key algorithm is unsupported");
        }
        Objects.requireNonNull(publicKey, "publicKey");
        if (publicKey.length == 0 || publicKey.length > MAX_PUBLIC_KEY_BYTES) {
            throw new IllegalArgumentException("Recovery public key is invalid");
        }
        publicKey = Arrays.copyOf(publicKey, publicKey.length);
    }

    @Override
    public byte @NonNull [] publicKey() {
        return Arrays.copyOf(publicKey, publicKey.length);
    }

    @Override
    public @NonNull String toString() {
        return "RecoveryPublicKey[enrollmentId=%s, generation=%d, keyAlgorithm=%s, publicKey=[REDACTED %d bytes]]"
                .formatted(enrollmentId, generation, keyAlgorithm, publicKey.length);
    }
}
