package top.focess.keystead.service;

import java.util.List;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

public record SyncImportReport(
        int imported, int skipped, @NonNull List<SyncImportConflict> conflicts) {

    public SyncImportReport {
        conflicts = List.copyOf(Objects.requireNonNull(conflicts, "conflicts"));
        if (imported < 0) {
            throw new IllegalArgumentException("Imported count must not be negative");
        }
        if (skipped < 0) {
            throw new IllegalArgumentException("Skipped count must not be negative");
        }
    }
}
