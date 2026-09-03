package top.focess.keystead.service;

import java.util.List;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

/**
 * Outcome of a sync import: counts of imported and skipped records, plus the per-row conflicts that
 * caused a skip.
 *
 * @param imported the number of records written
 * @param skipped the number of records skipped due to conflicts
 * @param conflicts the per-row conflicts explaining skipped rows
 * @param rejected the rows rejected before mutation because authentication or routing failed
 */
public record SyncImportReport(
        int imported,
        int skipped,
        @NonNull List<SyncImportConflict> conflicts,
        @NonNull List<SyncImportRejection> rejected) {

    /** Validates the record components. */
    public SyncImportReport {
        conflicts = List.copyOf(Objects.requireNonNull(conflicts, "conflicts"));
        rejected = List.copyOf(Objects.requireNonNull(rejected, "rejected"));
        if (imported < 0) {
            throw new IllegalArgumentException("Imported count must not be negative");
        }
        if (skipped < 0) {
            throw new IllegalArgumentException("Skipped count must not be negative");
        }
    }

    /** Compatibility constructor for reports with no authentication rejection.
     *
     * @param imported the number of records written
     * @param skipped the number of records skipped due to conflicts
     * @param conflicts the per-row conflicts explaining skipped rows */
    public SyncImportReport(
            int imported, int skipped, @NonNull List<SyncImportConflict> conflicts) {
        this(imported, skipped, conflicts, List.of());
    }
}
