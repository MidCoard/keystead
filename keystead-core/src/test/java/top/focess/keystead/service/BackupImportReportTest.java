package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import org.junit.jupiter.api.Test;

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
}
