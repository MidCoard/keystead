package top.focess.keystead.service;

import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.SecretId;

public record BackupConflict(
        @NonNull SecretId secretId, long existingRevision, long incomingRevision) {

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
