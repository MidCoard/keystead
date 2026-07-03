package top.focess.keystead.service;

import java.util.Objects;
import org.jspecify.annotations.NonNull;

public record EncryptedSyncRecord(
        @NonNull String vaultId,
        @NonNull String secretId,
        long revision,
        @NonNull String secretType,
        @NonNull String encryptedProfile,
        @NonNull String envelope,
        boolean deleted) {

    public EncryptedSyncRecord {
        Objects.requireNonNull(vaultId, "vaultId");
        Objects.requireNonNull(secretId, "secretId");
        Objects.requireNonNull(secretType, "secretType");
        Objects.requireNonNull(encryptedProfile, "encryptedProfile");
        Objects.requireNonNull(envelope, "envelope");
        if (revision <= 0) {
            throw new IllegalArgumentException("Record revision must be positive");
        }
    }
}
