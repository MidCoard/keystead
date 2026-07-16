package top.focess.keystead.model;

import java.util.Objects;
import org.jspecify.annotations.NonNull;

/**
 * An encrypted secret record: vault id, metadata, encrypted payload, and revision.
 *
 * @param vaultId the vault containing the secret
 * @param metadata the non-secret metadata
 * @param payload the encrypted envelope
 * @param revision the positive record revision; must match the metadata revision
 */
public record EncryptedSecretRecord(
        @NonNull VaultId vaultId,
        @NonNull SecretMetadata metadata,
        @NonNull EncryptedEnvelope payload,
        long revision) {

    /** Validates the record components. */
    public EncryptedSecretRecord {
        Objects.requireNonNull(vaultId, "vaultId");
        Objects.requireNonNull(metadata, "metadata");
        Objects.requireNonNull(payload, "payload");
        if (revision <= 0) {
            throw new IllegalArgumentException("Record revision must be positive");
        }
        if (revision != metadata.revision()) {
            throw new IllegalArgumentException("Record revision must match metadata revision");
        }
    }
}
