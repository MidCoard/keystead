package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import top.focess.keystead.model.SecretId;

class BackupImportReportTest {

    @Test
    void rejectsNegativeCounters() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new BackupImportReport(-1, 0, 0, 0, List.of()));
        assertThrows(
                IllegalArgumentException.class,
                () -> new BackupImportReport(0, -1, 0, 0, List.of()));
        assertThrows(
                IllegalArgumentException.class,
                () -> new BackupImportReport(0, 0, -1, 0, List.of()));
        assertThrows(
                IllegalArgumentException.class,
                () -> new BackupImportReport(0, 0, 0, -1, List.of()));
    }

    @Test
    void rejectsMoreConflictsThanSkippedRows() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new BackupImportReport(0, 0, 0, 0, List.of(conflict())));
    }

    private static BackupConflict conflict() {
        return new BackupConflict(new SecretId(new UUID(0L, 1L)), 2L, 1L);
    }
}
