package top.focess.keystead.store;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.*;

/**
 * Durable persistence abstraction for an opened single-file vault.
 *
 * <p>A {@code VaultStore} is bound to exactly one vault file: it holds the unlocked vault key and the
 * decrypted record set in memory, and rewrites the whole container atomically on every mutation.
 * There is no vault id; identity is implicit in the file the store was opened against. Mutations are
 * coordinated through {@link #commitMutation}, which assigns the next monotonic revision.
 * {@link #commitVaultKeyRotation} is optional and defaults to unsupported. Implementations must keep
 * revisions positive and monotonic within a vault.
 */
public interface VaultStore {

    /** Persists the given vault header, rejecting timestamp regressions.
     *
     * @param header the vault header to persist */
    void saveVaultHeader(@NonNull VaultHeader header);

    /** Loads the vault header for this vault, if present.
     *
     * @return the vault header, or empty if no vault exists */
    @NonNull Optional<VaultHeader> loadVaultHeader();

    /** Returns the next monotonic revision for this vault.
     *
     * @return the next positive monotonic revision */
    long nextRevision();

    /** Records the highest revision seen for this vault, if it advances the stored value.
     *
     * @param revision the revision to record; must not be negative */
    void recordRevision(long revision);

    /** Commits a mutation atomically, assigning the next monotonic revision.
     *
     * @param mutation the mutation to commit */
    default void commitMutation(@NonNull VaultMutation mutation) {
        Objects.requireNonNull(mutation, "mutation");
        synchronized (this) {
            mutation.commit(nextRevision());
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

    /** Loads the encrypted secret record for the given secret id, if present and not hidden by a
     * newer tombstone.
     *
     * @param secretId the secret identifier
     * @return the encrypted secret record, or empty if absent or hidden */
    @NonNull Optional<EncryptedSecretRecord> loadSecretRecord(@NonNull SecretId secretId);

    /** Deletes the encrypted secret record for the given secret id, if present.
     *
     * @param secretId the secret identifier */
    void deleteSecretRecord(@NonNull SecretId secretId);

    /** Persists the given deleted secret record (tombstone), advancing the vault revision.
     *
     * @param record the deleted secret record to persist */
    void saveDeletedSecretRecord(@NonNull DeletedSecretRecord record);

    /** Loads the deleted secret record for the given secret id, if present and not hidden by a newer
     * active record.
     *
     * @param secretId the secret identifier
     * @return the deleted secret record, or empty if absent or hidden */
    @NonNull Optional<DeletedSecretRecord> loadDeletedSecretRecord(@NonNull SecretId secretId);

    /** Deletes the deleted secret record for the given secret id, if present.
     *
     * @param secretId the secret identifier */
    void deleteDeletedSecretRecord(@NonNull SecretId secretId);

    /** Lists the metadata of all non-hidden secret records for this vault.
     *
     * @return the non-hidden secret metadata, sorted by secret id */
    @NonNull List<SecretMetadata> listMetadata();

    /** Lists all non-hidden encrypted secret records for this vault.
     *
     * @return the non-hidden encrypted secret records, sorted by secret id */
    @NonNull List<EncryptedSecretRecord> listSecretRecords();

    /** Lists all non-hidden deleted secret records for this vault.
     *
     * @return the non-hidden deleted secret records, sorted by secret id */
    @NonNull List<DeletedSecretRecord> listDeletedSecretRecords();
}
