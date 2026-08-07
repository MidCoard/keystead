package top.focess.keystead.service;

import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.SecretMetadata;

/**
 * Decoded payload of a previewed sync record, exposed as one of the three typed secret views.
 *
 * <p>Returned inside a {@link SyncRecordPreview} by {@link VaultHandle#previewSyncRecord}. It is
 * valid only for the duration of the preview callback; the handle wipes the decoded secret material
 * when the callback returns, so callers must not retain references to the views.
 *
 * <p>Pattern-match the variant to access the typed view, then read its fields through the view's
 * own short-lived callbacks (for example {@link LoginSecretView#withPassword}).
 */
public sealed interface SyncPayloadView {

    /** Returns the secret's non-secret metadata.
     *
     * @return the secret's non-secret metadata */
    @NonNull SecretMetadata metadata();

    /** A decoded login-password payload. */
    record Login(@NonNull SecretMetadata metadata, @NonNull LoginSecretView view)
            implements SyncPayloadView {}

    /** A decoded secure-note payload. */
    record Note(@NonNull SecretMetadata metadata, @NonNull SecureNoteView view)
            implements SyncPayloadView {}

    /** A decoded structured-secret payload. */
    record Structured(@NonNull SecretMetadata metadata, @NonNull StructuredSecretView view)
            implements SyncPayloadView {}
}
