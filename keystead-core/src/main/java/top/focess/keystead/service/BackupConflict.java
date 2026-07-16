package top.focess.keystead.service;

import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.SecretId;

/**
 * A row skipped during backup restore because a local revision at least as new already exists.
 *
 * @param secretId the conflicting secret
 * @param existingRevision the local revision that won
 * @param incomingRevision the archive revision that was skipped
 */
public record BackupConflict(
        @NonNull SecretId secretId, long existingRevision, long incomingRevision) {

    /** Validates the record components. */
    public BackupConflict {
        Objects.requireNonNull(secretId, "secretId");
        if (existingRevision <= 0) {
            throw new IllegalArgumentException("Existing revision must be positive");
        }
        if (incomingRevision <= 0) {
            throw new IllegalArgumentException("Incoming revision must be positive");
        }
        if (existingRevision < incomingRevision) {
            throw new IllegalArgumentException(
                    "Existing revision must be greater than or equal to incoming revision");
        }
    }
}
