package top.focess.keystead.service;

import java.util.Objects;
import org.jspecify.annotations.NonNull;

/** Safe, ciphertext-free detail for one rejected encrypted sync row. */
public record SyncImportRejection(
        @NonNull String secretId, long revision, @NonNull SyncImportRejectionReason reason) {

    public SyncImportRejection {
        Objects.requireNonNull(secretId, "secretId");
        Objects.requireNonNull(reason, "reason");
        if (secretId.isBlank() || revision <= 0) {
            throw new IllegalArgumentException("Rejected sync record identity is invalid");
        }
    }
}
