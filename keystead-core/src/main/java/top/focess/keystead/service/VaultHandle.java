package top.focess.keystead.service;

import java.util.List;
import java.util.function.Consumer;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.KeyId;
import top.focess.keystead.model.SecretId;
import top.focess.keystead.model.SecretMetadata;
import top.focess.keystead.model.SecretType;
import top.focess.keystead.model.VaultFingerprint;

/**
 * A live, unlocked view of a vault for performing typed secret operations.
 *
 * <p>A handle owns the unwrapped vault key for its lifetime. {@link #close()} destroys that key
 * material and rejects all further operations. While a key rotation is {@link
 * #prepareVaultKeyRotation prepared}, mutating operations are rejected so the live key set stays
 * stable until the rotation is committed or abandoned.
 *
 * <p>Secret plaintext is never returned directly. Drafts accept {@link
 * top.focess.keystead.memory.SecretBuffer} inputs and views expose decoded fields only inside a
 * caller-supplied callback; callers should avoid copying plaintext into immutable {@link String}
 * values and should keep callbacks short-lived.
 *
 * <p>Handles are safe for concurrent use by multiple threads: each operation is atomic with
 * respect to other operations on the same handle. Compound sequences that span multiple calls
 * (for example, inspecting {@link #listSecrets()} and then deleting based on the result) are not
 * atomic and require external coordination when concurrent mutation is possible.
 */
public interface VaultHandle extends AutoCloseable {

    /** Returns the stored routing fingerprint of the vault this handle is bound to.
     *
     * <p>A new vault initially derives this non-secret value from its first passphrase and KDF salt.
     * It is then stored and preserved across vault-key rotations, restores, provisioning, and local
     * passphrase changes, and may be disclosed to a sync server as an opaque routing token.
     *
     * @return the vault fingerprint */
    @NonNull VaultFingerprint vaultFingerprint();

    /** Returns the id of the currently active vault key.
     *
     * @return the vault key id */
    @NonNull KeyId vaultKeyId();

    /**
     * Creates a complete encrypted backup archive protected by an independent backup password.
     * The returned archive contains no raw vault key or plaintext secret.
     *
     * @param backupPassword caller-owned backup password
     * @return complete encrypted backup material
     */
    @NonNull FullBackupArchive createFullBackup(char @NonNull [] backupPassword);

    /**
     * Saves a new login-password secret and returns its assigned id.
     *
     * @param draftConsumer callback that populates a {@link LoginDraft}; the draft is validated and
     *     closed by this method
     * @return the id of the newly saved secret
     * @throws ValidationException if required fields are missing or invalid
     */
    @NonNull SecretId saveLogin(@NonNull Consumer<LoginDraft> draftConsumer);

    /**
     * Replaces an existing login-password secret with a new draft, advancing its revision.
     *
     * @param secretId the secret to replace
     * @param draftConsumer callback that populates the replacement {@link LoginDraft}
     * @throws ValidationException if the secret does not exist or is not a login password
     */
    void updateLogin(@NonNull SecretId secretId, @NonNull Consumer<LoginDraft> draftConsumer);

    /**
     * Decrypts a login-password secret and exposes its fields inside the callback.
     *
     * @param secretId the secret to read
     * @param viewConsumer callback that receives a short-lived {@link LoginSecretView}
     * @throws ValidationException if the secret does not exist or is not a login password
     */
    void withLogin(@NonNull SecretId secretId, @NonNull Consumer<LoginSecretView> viewConsumer);

    /**
     * Saves a new secure note and returns its assigned id.
     *
     * @param draftConsumer callback that populates a {@link SecureNoteDraft}
     * @return the id of the newly saved note
     * @throws ValidationException if required fields are missing or invalid
     */
    @NonNull SecretId saveSecureNote(@NonNull Consumer<SecureNoteDraft> draftConsumer);

    /**
     * Replaces an existing secure note with a new draft, advancing its revision.
     *
     * @param secretId the note to replace
     * @param draftConsumer callback that populates the replacement draft
     * @throws ValidationException if the secret does not exist or is not a secure note
     */
    void updateSecureNote(
            @NonNull SecretId secretId, @NonNull Consumer<SecureNoteDraft> draftConsumer);

    /**
     * Decrypts a secure note and exposes its body inside the callback.
     *
     * @param secretId the note to read
     * @param viewConsumer callback that receives a short-lived {@link SecureNoteView}
     * @throws ValidationException if the secret does not exist or is not a secure note
     */
    void withSecureNote(@NonNull SecretId secretId, @NonNull Consumer<SecureNoteView> viewConsumer);

    /**
     * Saves a new structured secret of the given type and returns its assigned id.
     *
     * <p>Only structured types are accepted; {@link SecretType#LOGIN_PASSWORD} and {@link
     * SecretType#SECURE_NOTE} use dedicated payload formats and must be saved through {@link
     * #saveLogin} or {@link #saveSecureNote}.
     *
     * @param type the structured secret type
     * @param draftConsumer callback that populates a {@link StructuredSecretDraft}
     * @return the id of the newly saved secret
     * @throws ValidationException if the type uses a dedicated format or required fields are missing
     */
    @NonNull SecretId saveSecret(
            @NonNull SecretType type, @NonNull Consumer<StructuredSecretDraft> draftConsumer);

    /**
     * Replaces an existing structured secret with a new draft, advancing its revision.
     *
     * @param secretId the secret to replace
     * @param draftConsumer callback that populates the replacement {@link StructuredSecretDraft}
     * @throws ValidationException if the secret does not exist or uses a dedicated format
     */
    void updateSecret(
            @NonNull SecretId secretId, @NonNull Consumer<StructuredSecretDraft> draftConsumer);

    /**
     * Decrypts a structured secret and exposes its fields inside the callback.
     *
     * @param secretId the secret to read
     * @param viewConsumer callback that receives a short-lived {@link StructuredSecretView}
     * @throws ValidationException if the secret does not exist or uses a dedicated format
     */
    void withSecret(
            @NonNull SecretId secretId, @NonNull Consumer<StructuredSecretView> viewConsumer);

    /**
     * Deletes a secret by recording a tombstone at the next revision and removing the active row.
     *
     * @param secretId the secret to delete
     */
    void deleteSecret(@NonNull SecretId secretId);

    /** Returns metadata for every active secret in the vault, in store order.
     *
     * @return the secret metadata */
    @NonNull List<SecretMetadata> listSecrets();

    /**
     * Exports encrypted records and tombstones with revision strictly greater than {@code
     * sinceRevision}, ordered by revision then secret id. To create a stable DEK-keyed content key,
     * this call decrypts each selected payload into a temporary buffer and wipes that buffer after
     * constructing the encrypted export row.
     *
     * @param sinceRevision the exclusive lower revision bound; must not be negative
     * @return the encrypted rows to send to a sync server
     * @throws ValidationException if {@code sinceRevision} is negative
     */
    @NonNull List<EncryptedSyncRecord> exportRecordsSince(long sinceRevision);

    /**
     * Imports encrypted sync records and returns the number written.
     *
     * <p>Older remote rows never overwrite newer local state, and mixed-vault batches are rejected
     * before any row is written. Use {@link #importRecordsWithReport} to inspect skipped and
     * conflicting rows.
     *
     * @param records the encrypted rows received from a sync server
     * @return the number of records imported
     * @throws ValidationException if the batch is mixed-vault, has duplicate ids, or is malformed
     */
    int importRecords(@NonNull List<EncryptedSyncRecord> records);

    /**
     * Imports encrypted sync records and returns a report with imported, skipped, and conflicting
     * rows.
     *
     * @param records the encrypted rows received from a sync server
     * @return a report describing the import outcome
     * @throws ValidationException if the batch is mixed-vault, has duplicate ids, or is malformed
     */
    @NonNull SyncImportReport importRecordsWithReport(@NonNull List<EncryptedSyncRecord> records);

    /**
     * Explicitly accepts an authenticated incoming value or deletion as a new local revision.
     * Call only after the user chooses this version when resolving a conflict. The secret id is
     * preserved and the new revision exceeds both the incoming and all observed local revisions.
     *
     * @param record the user-selected encrypted sync record
     * @throws ValidationException if the record cannot be authenticated or its revision is exhausted
     */
    void resolveSyncRecord(@NonNull EncryptedSyncRecord record);

    /**
     * Decrypts a single sync record under this vault's DEK and exposes its contents inside the
     * callback <em>without</em> storing it, so the user can compare a server record against local
     * state before merging.
     *
     * <p>Validation matches {@link #importRecordsWithReport}: the fingerprint must match this vault,
     * the profile and payload must decrypt under the open DEK, and the recomputed contentKey must
     * equal the record's. A record that fails (foreign DEK, pre-rotation leftover, or tampered)
     * throws {@link ValidationException}; the caller can treat that as "not valid for this vault" and
     * exclude it from the merge. The decoded payload is wiped when the callback returns.
     *
     * @param record the encrypted sync record received from a sync server
     * @param consumer callback that receives a short-lived {@link SyncRecordPreview}
     * @throws ValidationException if the record is mixed-vault, malformed, or fails content-key
     *     verification
     */
    void previewSyncRecord(
            @NonNull EncryptedSyncRecord record, @NonNull Consumer<SyncRecordPreview> consumer);

    /**
     * Wraps the current vault key for another device's public key.
     *
     * @param devicePublicKey the recipient device's public key
     * @param context caller-owned binding context; wiped by the caller
     * @return the device-wrapped vault key bytes
     */
    byte @NonNull [] wrapVaultKeyForDevice(
            byte @NonNull [] devicePublicKey, byte @NonNull [] context);

    /**
     * Wraps the current vault key for another device and returns it as a typed package.
     *
     * @param devicePublicKey the recipient device's public key
     * @param context caller-owned binding context; wiped by the caller
     * @return the device-wrapped vault key package
     * @see #wrapVaultKeyForDevice
     */
    @NonNull DeviceVaultKeyPackage wrapVaultKeyPackageForDevice(
            byte @NonNull [] devicePublicKey, byte @NonNull [] context);

    /**
     * Wraps the current vault key with a new local master passphrase and appends a PASSPHRASE slot.
     * The data-encryption key, vault fingerprint, and encrypted records are unchanged. This is used
     * after server provisioning so the temporary transfer-device slot can be removed safely.
     *
     * @param passphrase caller-owned local master passphrase; wiped by the caller
     * @return the key id of the new passphrase slot
     * @throws ValidationException if the passphrase is empty, a passphrase slot already exists, or
     *     the header is full
     */
    @NonNull KeyId addPassphrase(char @NonNull [] passphrase);

    /**
     * Wraps the current vault key for the given device public key and appends a DEVICE slot to the
     * vault header, so that device can thereafter unlock the vault without a passphrase. The
     * data-encryption key is unchanged and no secret records are re-encrypted; the existing
     * passphrase slot (and any other slots) are preserved.
     *
     * @param devicePublicKey the recipient device's public key
     * @param context caller-owned binding context; wiped by the caller
     * @return the key id of the newly added device slot
     * @throws ValidationException if the header is full
     * @throws top.focess.keystead.store.StoreException if the updated header cannot be persisted
     */
    @NonNull KeyId addDeviceKey(byte @NonNull [] devicePublicKey, byte @NonNull [] context);

    /**
     * Removes the DEVICE slot with the given key id from the vault header, revoking that device's
     * passphrase-less access. The vault must retain at least one slot.
     *
     * @param slotKeyId the key id of the device slot to remove (as returned by {@link #addDeviceKey})
     * @throws ValidationException if no matching device slot exists or it is the last remaining slot
     */
    void removeDeviceKey(@NonNull KeyId slotKeyId);

    /**
     * Prepares a vault-key rotation: generates the next key and re-encrypts current records without
     * committing, so recipient packages can be collected first.
     *
     * <p>While prepared, mutating operations on this handle are rejected. Commit via the returned
     * {@link PreparedVaultKeyRotation}, or close it to abandon the rotation.
     *
     * @return the prepared, uncommitted rotation
     */
    @NonNull PreparedVaultKeyRotation prepareVaultKeyRotation();

    /**
     * Resumes a previously prepared rotation from a device-wrapped staged package, for example
     * after a restart.
     *
     * @param stagedPackage the staged package produced by the original preparation
     * @param devicePrivateKey caller-owned device private key; wiped by the caller
     * @param context caller-owned binding context; wiped by the caller
     * @return the resumed, uncommitted rotation
     * @throws ValidationException if the staged package is unsupported or does not contain a new key
     */
    @NonNull PreparedVaultKeyRotation resumeVaultKeyRotation(
            @NonNull DeviceVaultKeyPackage stagedPackage,
            byte @NonNull [] devicePrivateKey,
            byte @NonNull [] context);

    /** Returns whether this handle has been closed and its key destroyed.
     *
     * @return {@code true} if this handle has been closed and its key destroyed */
    boolean isClosed();

    /**
     * Closes this handle and destroys its vault key material. After closing, every operation on
     * this handle throws {@link IllegalStateException}. Closing an already-closed handle is a no-op.
     */
    @Override
    void close();
}
