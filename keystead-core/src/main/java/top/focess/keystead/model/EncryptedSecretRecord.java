package top.focess.keystead.model;

import java.util.Objects;
import org.jspecify.annotations.NonNull;

/**
 * An encrypted secret record: metadata, encrypted payload, and revision. A v2 vault is
 * vault-scoped on disk (one file), so records carry no stored vault identifier; the
 * passphrase-derived {@link VaultFingerprint} is held by the owning handle and mixed into each
 * record's AAD at encrypt/decrypt time.
 *
 * @param metadata the non-secret metadata
 * @param payload the encrypted envelope
 * @param revision the positive record revision; must match the metadata revision
 */
public record EncryptedSecretRecord(
        @NonNull SecretMetadata metadata, @NonNull EncryptedEnvelope payload, long revision) {

    /** Validates the record components. */
    public EncryptedSecretRecord {
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
