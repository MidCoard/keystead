package top.focess.keystead.recovery;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.crypto.CryptoAlgorithmRegistry;

/**
 * Canonical public request that an existing verified device may approve to authorize recovery for a
 * new device. Key-bearing fields are defensively copied and redacted in {@link #toString()}.
 *
 * @param formatVersion the request format version
 * @param requestId the unique request identifier
 * @param username the account username the request targets
 * @param nonce the single-use nonce
 * @param expiresAt the whole-second expiry time
 * @param deviceId the requesting device's identifier
 * @param proofKeyAlgorithm the proof-of-possession key algorithm
 * @param proofPublicKey the proof-of-possession public key
 * @param wrappingKeyAlgorithm the approved device key-package algorithm
 * @param wrappingPublicKey the public key to wrap the recovered vault key for
 */
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

    /** The recovery device request format version supported by this record. */
    public static final int FORMAT_VERSION = 1;

    private static final int MAX_KEY_BYTES = 64 * 1024;

    /** Validates and defensively copies the record components. */
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

    /** Returns a defensive copy of the proof-of-possession public key.
     *
     * @return a defensive copy of the proof public key */
    @Override
    public byte @NonNull [] proofPublicKey() {
        return Arrays.copyOf(proofPublicKey, proofPublicKey.length);
    }

    /** Returns a defensive copy of the wrapping public key.
     *
     * @return a defensive copy of the wrapping public key */
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
