package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class SyncImportConflictTest {

    @Test
    void rejectsBlankConflictIdentity() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new SyncImportConflict(" ", secretId(), 2L, 1L, false, true));
        assertThrows(
                IllegalArgumentException.class,
                () -> new SyncImportConflict(vaultId(), " ", 2L, 1L, false, true));
    }

    @Test
    void rejectsRemoteRevisionNewerThanLocalRevision() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new SyncImportConflict(vaultId(), secretId(), 1L, 2L, true, false));
    }

    private static String vaultId() {
        return "60000000-0000-0000-0000-000000000001";
    }

    private static String secretId() {
        return "70000000-0000-0000-0000-000000000001";
    }
}
