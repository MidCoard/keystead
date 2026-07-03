package top.focess.keystead.service;

import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.SecretId;

public record BackupConflict(
        @NonNull SecretId secretId, long existingRevision, long incomingRevision) {

    public BackupConflict {
        Objects.requireNonNull(secretId, "secretId");
    }
}
