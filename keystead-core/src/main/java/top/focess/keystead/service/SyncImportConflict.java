package top.focess.keystead.service;

import java.util.Objects;
import org.jspecify.annotations.NonNull;

public record SyncImportConflict(
        @NonNull String vaultId,
        @NonNull String secretId,
        long localRevision,
        long remoteRevision,
        boolean localDeleted,
        boolean remoteDeleted) {

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
