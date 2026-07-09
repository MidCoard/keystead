package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class SyncImportConflictTest {

    @Test
    void rejectsRemoteRevisionNewerThanLocalRevision() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new SyncImportConflict(
                                "60000000-0000-0000-0000-000000000001",
                                "70000000-0000-0000-0000-000000000001",
                                1L,
                                2L,
                                true,
                                false));
    }
}
