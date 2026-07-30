package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import top.focess.keystead.crypto.KdfParameters;
import top.focess.keystead.model.KeyId;
import top.focess.keystead.model.KeySlot;
import top.focess.keystead.model.SlotType;
import top.focess.keystead.model.VaultFingerprint;
import top.focess.keystead.model.VaultHeader;

class BackupReadResultTest {

    private static final VaultFingerprint FINGERPRINT =
            VaultFingerprint.fromHexString("0011223344556677");

    @Test
    void rejectsNegativeUnsupportedCount() {
        assertThrows(
                IllegalArgumentException.class, () -> new BackupReadResult(emptyArchive(), -1));
    }

    private static BackupArchive emptyArchive() {
        return new BackupArchive(
                new BackupManifest(
                        VaultBackupService.FORMAT_VERSION,
                        FINGERPRINT,
                        0,
                        0,
                        Instant.parse("2026-07-03T00:00:00Z")),
                header(),
                List.of(),
                List.of());
    }

    private static VaultHeader header() {
        return new VaultHeader(
                1,
                FINGERPRINT,
                new KeyId("vault-key"),
                List.of(
                        new KeySlot(
                                SlotType.PASSPHRASE,
                                new KeyId("passphrase"),
                                KdfParameters.pbkdf2(
                                        "PBKDF2WithHmacSHA256", new byte[] {1, 2, 3}, 120_000),
                                new byte[] {4, 5, 6})),
                Instant.parse("2026-07-02T00:00:00Z"),
                Instant.parse("2026-07-02T00:01:00Z"));
    }
}
