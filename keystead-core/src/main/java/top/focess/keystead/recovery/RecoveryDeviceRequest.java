package top.focess.keystead.recovery;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.crypto.CryptoAlgorithmRegistry;

/** Canonical public request that an existing verified device may approve. */
public record RecoveryDeviceRequest(
        int formatVersion,
        @NonNull String requestId,
        @NonNull String username,
        @NonNull String nonce,
        @NonNull Instant expiresAt,
        @NonNull String deviceId,
        @NonNull String proofKeyAlgorithm,
        byte @NonNull [] proofPublicKey,
        @NonNull String wrappingKeyAlgorithm,
        byte @NonNull [] wrappingPublicKey) {

    public static final int FORMAT_VERSION = 1;
    private static final int MAX_KEY_BYTES = 64 * 1024;

    public RecoveryDeviceRequest {
        if (formatVersion != FORMAT_VERSION) {
            throw new IllegalArgumentException("Recovery device request format is unsupported");
        }
        requestId = requireText(requestId, "requestId", 128);
        username = requireText(username, "username", 255);
        nonce = requireText(nonce, "nonce", 512);
        Objects.requireNonNull(expiresAt, "expiresAt");
        if (expiresAt.getNano() != 0) {
            throw new IllegalArgumentException("Recovery request expiry must use whole seconds");
        }
        deviceId = requireText(deviceId, "deviceId", 255);
        proofKeyAlgorithm = requireText(proofKeyAlgorithm, "proofKeyAlgorithm", 64);
        Objects.requireNonNull(proofPublicKey, "proofPublicKey");
        wrappingKeyAlgorithm = requireText(wrappingKeyAlgorithm, "wrappingKeyAlgorithm", 64);
        if (!CryptoAlgorithmRegistry.isApprovedDeviceKeyPackage(wrappingKeyAlgorithm)) {
            throw new IllegalArgumentException("Recovery device wrapping algorithm is unsupported");
        }
        Objects.requireNonNull(wrappingPublicKey, "wrappingPublicKey");
        if (proofPublicKey.length == 0
                || proofPublicKey.length > MAX_KEY_BYTES
                || wrappingPublicKey.length == 0
                || wrappingPublicKey.length > MAX_KEY_BYTES) {
            throw new IllegalArgumentException("Recovery device public key is invalid");
        }
        proofPublicKey = Arrays.copyOf(proofPublicKey, proofPublicKey.length);
        wrappingPublicKey = Arrays.copyOf(wrappingPublicKey, wrappingPublicKey.length);
    }

    @Override
    public byte @NonNull [] proofPublicKey() {
        return Arrays.copyOf(proofPublicKey, proofPublicKey.length);
    }

    @Override
    public byte @NonNull [] wrappingPublicKey() {
        return Arrays.copyOf(wrappingPublicKey, wrappingPublicKey.length);
    }

    @Override
    public @NonNull String toString() {
        return "RecoveryDeviceRequest[formatVersion=%d, requestId=%s, username=%s, nonce=[REDACTED], expiresAt=%s, deviceId=%s, proofKeyAlgorithm=%s, proofPublicKey=[REDACTED %d bytes], wrappingKeyAlgorithm=%s, wrappingPublicKey=[REDACTED %d bytes]]"
                .formatted(
                        formatVersion,
                        requestId,
                        username,
                        expiresAt,
                        deviceId,
                        proofKeyAlgorithm,
                        proofPublicKey.length,
                        wrappingKeyAlgorithm,
                        wrappingPublicKey.length);
    }

    private static @NonNull String requireText(
            @NonNull String value, @NonNull String field, int maxLength) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()
                || value.length() > maxLength
                || value.chars().anyMatch(character -> Character.isISOControl(character))) {
            throw new IllegalArgumentException(field + " is invalid");
        }
        return value;
    }
}
