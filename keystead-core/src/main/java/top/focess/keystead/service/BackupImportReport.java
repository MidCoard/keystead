package top.focess.keystead.service;

import java.util.List;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

public record BackupImportReport(
        int imported,
        int skipped,
        int unsupported,
        int tombstones,
        @NonNull List<BackupConflict> conflicts) {

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
