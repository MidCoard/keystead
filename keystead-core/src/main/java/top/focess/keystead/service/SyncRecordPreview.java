package top.focess.keystead.service;

import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.SecretId;
import top.focess.keystead.model.SecretMetadata;
import top.focess.keystead.model.SecretType;

/**
 * A decrypted, in-memory preview of a sync record, exposed inside a {@link
 * VaultHandle#previewSyncRecord} callback so the user can compare a server record against local
 * state <em>without</em> storing it.
 *
 * <p>Valid only for the duration of the callback; the handle wipes the decoded payload when the
 * callback returns. Pattern-match this sealed type to distinguish an active record (metadata plus
 * decoded payload) from a tombstone (identity, type, and revision only).
 */
public sealed interface SyncRecordPreview {

    /** An active record's preview: its metadata and decoded payload.
     *
     * @param metadata the record's non-secret metadata
     * @param payload the decoded payload view; valid only inside the preview callback */
    record Active(@NonNull SecretMetadata metadata, @NonNull SyncPayloadView payload)
            implements SyncRecordPreview {}

    /** A tombstone's preview: the deleted secret's identity, type, and revision.
     *
     * @param secretId the deleted secret's stable id
     * @param secretType the deleted secret's type
     * @param revision the revision at which the secret was deleted */
    record Deleted(@NonNull SecretId secretId, @NonNull SecretType secretType, long revision)
            implements SyncRecordPreview {}
}
