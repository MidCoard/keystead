package top.focess.keystead.service;

import java.util.Objects;
import org.jspecify.annotations.NonNull;

/**
 * A conflict between a local and remote sync record where the local revision is at least as new as
 * the remote revision.
 *
 * @param vaultId the vault id
 * @param secretId the secret id
 * @param localRevision the local revision that won
 * @param remoteRevision the remote revision that was skipped
 * @param localDeleted whether the local state is a tombstone
 * @param remoteDeleted whether the remote state is a tombstone
 */
public record SyncImportConflict(
        @NonNull String vaultId,
        @NonNull String secretId,
        long localRevision,
        long remoteRevision,
        boolean localDeleted,
        boolean remoteDeleted) {

    /** Validates the record components. */
    public SyncImportConflict {
        requireNotBlank(vaultId, "vaultId");
        requireNotBlank(secretId, "secretId");
        if (localRevision <= 0) {
            throw new IllegalArgumentException("Local revision must be positive");
        }
        if (remoteRevision <= 0) {
            throw new IllegalArgumentException("Remote revision must be positive");
        }
        if (localRevision < remoteRevision) {
            throw new IllegalArgumentException(
                    "Local revision must be greater than or equal to remote revision");
        }
    }

    private static void requireNotBlank(@NonNull String value, @NonNull String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank()) {
            throw new IllegalArgumentException(field + " must not be blank");
        }
    }
}
