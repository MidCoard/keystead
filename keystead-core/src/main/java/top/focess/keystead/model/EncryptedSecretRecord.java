package top.focess.keystead.model;

import java.util.Objects;

public record EncryptedSecretRecord(
    VaultId vaultId,
    SecretMetadata metadata,
    EncryptedEnvelope payload,
    long revision
) {

    public EncryptedSecretRecord {
        Objects.requireNonNull(vaultId, "vaultId");
        Objects.requireNonNull(metadata, "metadata");
        Objects.requireNonNull(payload, "payload");
        if (revision < 0) {
            throw new IllegalArgumentException("Record revision must not be negative");
        }
    }
}
