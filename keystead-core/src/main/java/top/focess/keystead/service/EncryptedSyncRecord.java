package top.focess.keystead.service;

import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.SecretType;
import top.focess.keystead.model.SecurityLimits;

/**
 * An encrypted secret record exchanged with a sync server. Active records carry an encrypted profile
 * and envelope; deleted records carry neither.
 *
 * @param vaultId the vault id
 * @param secretId the secret id
 * @param revision the monotonic record revision
 * @param secretType the secret type name
 * @param encryptedProfile the encrypted profile envelope, or empty when deleted
 * @param envelope the encrypted payload envelope, or empty when deleted
 * @param deleted whether this record is a tombstone
 */
public record EncryptedSyncRecord(
        @NonNull String vaultId,
        @NonNull String secretId,
        long revision,
        @NonNull String secretType,
        @NonNull String encryptedProfile,
        @NonNull String envelope,
        boolean deleted) {

    /** Validates the record components. */
    public EncryptedSyncRecord {
        requireNotBlank(vaultId, "vaultId");
        requireNotBlank(secretId, "secretId");
        requireNotBlank(secretType, "secretType");
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
        if (deleted && (!encryptedProfile.isEmpty() || !envelope.isEmpty())) {
            throw new IllegalArgumentException("Deleted sync records must not carry envelopes");
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
