package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.UUID;
import org.junit.jupiter.api.Test;
import top.focess.keystead.model.SecretId;

class BackupConflictTest {

    @Test
    void rejectsNonPositiveExistingRevision() {
        assertThrows(IllegalArgumentException.class, () -> conflict(0L, 1L));
    }

    @Test
    void rejectsNonPositiveIncomingRevision() {
        assertThrows(IllegalArgumentException.class, () -> conflict(1L, 0L));
    }

    @Test
    void rejectsIncomingRevisionNewerThanExistingRevision() {
        assertThrows(IllegalArgumentException.class, () -> conflict(1L, 2L));
    }

    private static BackupConflict conflict(long existingRevision, long incomingRevision) {
        return new BackupConflict(
                new SecretId(new UUID(0L, 1L)), existingRevision, incomingRevision);
    }
}
