package top.focess.keystead.service;

import java.util.List;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

/**
 * Outcome of a backup restore: counts of imported, skipped, unsupported, and tombstone rows, plus the
 * per-row conflicts.
 *
 * @param imported the number of records written
 * @param skipped the number of rows skipped due to conflicts
 * @param unsupported the number of unsupported entries reported by the reader
 * @param tombstones the number of tombstones written
 * @param conflicts the per-row conflicts explaining skipped rows
 */
public record BackupImportReport(
        int imported,
        int skipped,
        int unsupported,
        int tombstones,
        @NonNull List<BackupConflict> conflicts) {

    /** Validates the record components. */
    public BackupImportReport {
        conflicts = List.copyOf(Objects.requireNonNull(conflicts, "conflicts"));
        if (imported < 0 || skipped < 0 || unsupported < 0 || tombstones < 0) {
            throw new IllegalArgumentException("Backup import counters must not be negative");
        }
        if (conflicts.size() > skipped) {
            throw new IllegalArgumentException(
                    "Backup import conflicts must not exceed skipped rows");
        }
    }
}
