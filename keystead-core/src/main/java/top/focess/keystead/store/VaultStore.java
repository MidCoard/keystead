package top.focess.keystead.store;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.*;

/**
 * Durable persistence abstraction for vault headers, secret records, tombstones, and revisions.
 *
 * <p>Mutations are coordinated through {@link #commitMutation}, which assigns the next monotonic
 * revision. {@link #commitVaultKeyRotation} is optional and defaults to unsupported.
 * Implementations must keep revisions positive and monotonic within a vault.
 */
public interface VaultStore {

    /** Persists the given vault header, rejecting vault-identity or timestamp regressions.
     *
     * @param header the vault header to persist */
    void saveVaultHeader(@NonNull VaultHeader header);

    /** Loads the vault header for the given vault id, if present.
     *
     * @param vaultId the vault identifier
     * @return the vault header, or empty if no vault exists for the id */
    @NonNull Optional<VaultHeader> loadVaultHeader(@NonNull VaultId vaultId);

    /** Returns the next monotonic revision for the given vault.
     *
     * @param vaultId the vault identifier
     * @return the next positive monotonic revision */
    long nextRevision(@NonNull VaultId vaultId);

    /** Records the highest revision seen for the given vault, if it advances the stored value.
     *
     * @param vaultId the vault identifier
     * @param revision the revision to record; must not be negative */
    void recordRevision(@NonNull VaultId vaultId, long revision);

    /** Commits a mutation atomically, assigning the next monotonic revision.
     *
     * @param vaultId the vault identifier
     * @param mutation the mutation to commit */
    default void commitMutation(@NonNull VaultId vaultId, @NonNull VaultMutation mutation) {
        Objects.requireNonNull(vaultId, "vaultId");
        Objects.requireNonNull(mutation, "mutation");
        synchronized (this) {
            mutation.commit(nextRevision(vaultId));
        }
    }

    /** Commits a vault key rotation, replacing the header and active secret records.
     *
     * @param rotation the rotation to commit
     * @throws UnsupportedOperationException if this store does not support key rotation */
    default void commitVaultKeyRotation(@NonNull VaultKeyRotation rotation) {
        throw new UnsupportedOperationException(
                "Vault key rotation is not supported by this store");
    }

    /** Persists the given encrypted secret record, advancing the vault revision.
     *
     * @param record the encrypted secret record to persist */
    void saveSecretRecord(@NonNull EncryptedSecretRecord record);

    /** Loads the encrypted secret record for the given vault and secret id, if present and not
     * hidden by a newer tombstone.
     *
     * @param vaultId the vault identifier
     * @param secretId the secret identifier
     * @return the encrypted secret record, or empty if absent or hidden */
    @NonNull Optional<EncryptedSecretRecord> loadSecretRecord(
            @NonNull VaultId vaultId, @NonNull SecretId secretId);

    /** Deletes the encrypted secret record for the given vault and secret id, if present.
     *
     * @param vaultId the vault identifier
     * @param secretId the secret identifier */
    void deleteSecretRecord(@NonNull VaultId vaultId, @NonNull SecretId secretId);

    /** Persists the given deleted secret record (tombstone), advancing the vault revision.
     *
     * @param record the deleted secret record to persist */
    void saveDeletedSecretRecord(@NonNull DeletedSecretRecord record);

    /** Loads the deleted secret record for the given vault and secret id, if present and not
     * hidden by a newer active record.
     *
     * @param vaultId the vault identifier
     * @param secretId the secret identifier
     * @return the deleted secret record, or empty if absent or hidden */
    @NonNull Optional<DeletedSecretRecord> loadDeletedSecretRecord(
            @NonNull VaultId vaultId, @NonNull SecretId secretId);

    /** Deletes the deleted secret record for the given vault and secret id, if present.
     *
     * @param vaultId the vault identifier
     * @param secretId the secret identifier */
    void deleteDeletedSecretRecord(@NonNull VaultId vaultId, @NonNull SecretId secretId);

    /** Lists the metadata of all non-hidden secret records for the given vault.
     *
     * @param vaultId the vault identifier
     * @return the non-hidden secret metadata, sorted by secret id */
    @NonNull List<SecretMetadata> listMetadata(@NonNull VaultId vaultId);

    /** Lists all non-hidden encrypted secret records for the given vault.
     *
     * @param vaultId the vault identifier
     * @return the non-hidden encrypted secret records, sorted by secret id */
    @NonNull List<EncryptedSecretRecord> listSecretRecords(@NonNull VaultId vaultId);

    /** Lists all non-hidden deleted secret records for the given vault.
     *
     * @param vaultId the vault identifier
     * @return the non-hidden deleted secret records, sorted by secret id */
    @NonNull List<DeletedSecretRecord> listDeletedSecretRecords(@NonNull VaultId vaultId);
}
