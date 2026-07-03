package top.focess.keystead.service;

import java.util.Objects;
import org.jspecify.annotations.NonNull;

public record BackupReadResult(@NonNull BackupArchive archive, int unsupported) {

    public BackupReadResult {
        Objects.requireNonNull(archive, "archive");
        if (unsupported < 0) {
            throw new IllegalArgumentException("Unsupported count must not be negative");
        }
    }
}
