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
    }
}
