package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import top.focess.keystead.model.KeyId;
import top.focess.keystead.model.VaultHeader;
import top.focess.keystead.model.VaultId;

class BackupReadResultTest {

    private static final VaultId VAULT_ID = new VaultId(new UUID(0L, 1L));

    @Test
    void rejectsUnsupportedCountLargerThanArchiveRows() {
        assertThrows(IllegalArgumentException.class, () -> new BackupReadResult(emptyArchive(), 1));
    }

    private static BackupArchive emptyArchive() {
        return new BackupArchive(
                new BackupManifest(
                        VaultBackupService.FORMAT_VERSION,
                        VAULT_ID,
                        0,
                        0,
                        Instant.parse("2026-07-03T00:00:00Z")),
                header(),
                List.of(),
                List.of());
    }

    private static VaultHeader header() {
        return new VaultHeader(
                VAULT_ID,
                1,
                "PBKDF2WithHmacSHA256",
                new byte[] {1, 2, 3},
                120_000,
                new KeyId("vault-key"),
                new byte[] {4, 5, 6},
                Instant.parse("2026-07-02T00:00:00Z"),
                Instant.parse("2026-07-02T00:01:00Z"));
    }
}
