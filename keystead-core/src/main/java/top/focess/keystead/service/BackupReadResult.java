package top.focess.keystead.service;

import java.util.Objects;
import org.jspecify.annotations.NonNull;

/**
 * Result of reading a backup stream: the parsed archive and a count of unsupported or corrupt entries
 * that could not be included.
 *
 * @param archive the parsed backup archive
 * @param unsupported the number of unsupported or corrupt entries skipped during reading
 */
public record BackupReadResult(@NonNull BackupArchive archive, int unsupported) {

    /** Validates the record components. */
    public BackupReadResult {
        Objects.requireNonNull(archive, "archive");
        if (unsupported < 0) {
            throw new IllegalArgumentException("Unsupported count must not be negative");
        }
        int archiveRows = archive.manifest().recordCount() + archive.manifest().tombstoneCount();
        if (unsupported > archiveRows) {
            throw new IllegalArgumentException(
                    "Unsupported count must not exceed archive row count");
        }
    }
}
