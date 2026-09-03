package top.focess.keystead.access;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.crypto.CryptoAlgorithmRegistry;

/**
 * Canonical public request for one server-login-scoped vault-key exchange.
 *
 * <p>The request deliberately contains no persistent device identifier or proof key. The exchange
 * private key exists only in the requesting client's authenticated login session.
 *
 * @param formatVersion the access-request format version
 * @param requestId the canonical request UUID
 * @param accountId the account requesting access
 * @param serverOrigin the server origin the request is bound to
 * @param expiresAt the whole-second expiry instant
 * @param keyAlgorithm the approved exchange-key algorithm
 * @param exchangePublicKey the ephemeral exchange public key
 */
public record VaultAccessRequest(
        int formatVersion,
        @NonNull String requestId,
        @NonNull String accountId,
        @NonNull String serverOrigin,
        @NonNull Instant expiresAt,
        @NonNull String keyAlgorithm,
        byte @NonNull [] exchangePublicKey) {

    /** The ephemeral access-request format version. */
    public static final int FORMAT_VERSION = 2;

    private static final int MAX_KEY_BYTES = 64 * 1024;

    /** Validates and defensively copies all components. */
    public VaultAccessRequest {
        if (formatVersion != FORMAT_VERSION) {
            throw new IllegalArgumentException("Vault access request format is unsupported");
        }
        requestId = requireUuid(requestId);
        accountId = requireText(accountId, "accountId", 255);
        serverOrigin = requireText(serverOrigin, "serverOrigin", 2048);
        Objects.requireNonNull(expiresAt, "expiresAt");
        if (expiresAt.getNano() != 0) {
            throw new IllegalArgumentException(
                    "Vault access request expiry must use whole seconds");
        }
        keyAlgorithm = requireText(keyAlgorithm, "keyAlgorithm", 64);
        if (!CryptoAlgorithmRegistry.isApprovedDeviceKeyPackage(keyAlgorithm)) {
            throw new IllegalArgumentException("Vault access exchange algorithm is unsupported");
        }
        Objects.requireNonNull(exchangePublicKey, "exchangePublicKey");
        if (exchangePublicKey.length == 0 || exchangePublicKey.length > MAX_KEY_BYTES) {
            throw new IllegalArgumentException("Vault access exchange public key is invalid");
        }
        exchangePublicKey = Arrays.copyOf(exchangePublicKey, exchangePublicKey.length);
    }

    /** Returns a defensive copy of the ephemeral exchange public key.
     *
     * @return a defensive copy of the public key */
    @Override
    public byte @NonNull [] exchangePublicKey() {
        return Arrays.copyOf(exchangePublicKey, exchangePublicKey.length);
    }

    @Override
    public @NonNull String toString() {
        return "VaultAccessRequest[formatVersion=%d, requestId=%s, accountId=%s, serverOrigin=%s, expiresAt=%s, keyAlgorithm=%s, exchangePublicKey=[REDACTED %d bytes]]"
                .formatted(
                        formatVersion,
                        requestId,
                        accountId,
                        serverOrigin,
                        expiresAt,
                        keyAlgorithm,
                        exchangePublicKey.length);
    }

    private static @NonNull String requireUuid(@NonNull String value) {
        requireText(value, "requestId", 36);
        try {
            if (!UUID.fromString(value).toString().equals(value)) {
                throw new IllegalArgumentException();
            }
            return value;
        } catch (IllegalArgumentException error) {
            throw new IllegalArgumentException("requestId is invalid", error);
        }
    }

    private static @NonNull String requireText(
            @NonNull String value, @NonNull String field, int maxLength) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()
                || value.length() > maxLength
                || value.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException(field + " is invalid");
        }
        return value;
    }
}
