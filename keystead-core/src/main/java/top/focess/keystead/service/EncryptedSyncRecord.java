package top.focess.keystead.service;

import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.SecretType;
import top.focess.keystead.model.SecurityLimits;

/**
 * An encrypted secret record exchanged with a sync server. Active records carry an encrypted profile
 * and envelope; deleted records carry an authenticated control envelope in {@code
 * encryptedProfile}. Legacy empty tombstones can still be decoded from old servers, but import
 * rejects them because they cannot be authenticated under the vault key.
 *
 * @param fingerprint the vault fingerprint (hex)
 * @param secretId the secret id
 * @param revision the monotonic record revision
 * @param secretType the secret type name
 * @param encryptedProfile the encrypted profile or authenticated deletion-control envelope
 * @param envelope the encrypted payload envelope, or empty when deleted
 * @param deleted whether this record is a tombstone
 * @param contentKey the claimed vault-keyed HMAC of the record plaintexts; it makes the event
 *     identity stable across re-exports and restores because ciphertext nonces no longer affect
 *     identity. The record structure alone cannot authenticate this caller-supplied value; an open
 *     receiving vault verifies it by decrypting and recomputing the HMAC.
 */
public record EncryptedSyncRecord(
        @NonNull String fingerprint,
        @NonNull String secretId,
        long revision,
        @NonNull String secretType,
        @NonNull String encryptedProfile,
        @NonNull String envelope,
        boolean deleted,
        @NonNull String contentKey) {

    /** Validates the record components. */
    public EncryptedSyncRecord {
        requireNotBlank(fingerprint, "fingerprint");
        requireNotBlank(secretId, "secretId");
        requireNotBlank(secretType, "secretType");
        requireNotBlank(contentKey, "contentKey");
        Objects.requireNonNull(encryptedProfile, "encryptedProfile");
        Objects.requireNonNull(envelope, "envelope");
        if (encryptedProfile.length() > SecurityLimits.MAX_ENCODED_SYNC_CHARACTERS) {
            throw new IllegalArgumentException("Encrypted sync profile exceeds the size limit");
        }
        if (envelope.length() > SecurityLimits.MAX_ENCODED_SYNC_CHARACTERS) {
            throw new IllegalArgumentException("Encrypted sync envelope exceeds the size limit");
        }
        if (revision <= 0) {
            throw new IllegalArgumentException("Record revision must be positive");
        }
        try {
            SecretType.valueOf(secretType);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Sync record secret type is unsupported", e);
        }
        if (deleted && !envelope.isEmpty()) {
            throw new IllegalArgumentException("Deleted sync records must not carry payloads");
        }
        if (!deleted && (encryptedProfile.isEmpty() || envelope.isEmpty())) {
            throw new IllegalArgumentException("Active sync records must carry envelopes");
        }
    }

    private static void requireNotBlank(@NonNull String value, @NonNull String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
