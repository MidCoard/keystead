package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.model.SecretType;

class SyncRecordPreviewTest {

    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-07-03T00:00:00Z"), ZoneOffset.UTC);

    @TempDir Path tempDir;

    private Path vaultFile() {
        return tempDir.resolve("vault.kv");
    }

    private static char[] master() {
        return "correct horse battery staple".toCharArray();
    }

    private static char[] chars(String value) {
        return value.toCharArray();
    }

    private static EncryptedSyncRecord saveLoginAndExport(VaultHandle vault) {
        try (SecretBuffer username = SecretBuffer.fromChars(chars("alice@example.com"));
                SecretBuffer password = SecretBuffer.fromChars(chars("secret-password"))) {
            vault.saveLogin(draft -> draft.title("GitHub").username(username).password(password));
        }
        return vault.exportRecordsSince(0).getFirst();
    }

    @Test
    void previewDecodesActiveLoginRecord() {
        VaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        try (VaultHandle vault =
                service.createVault(new CreateVaultRequest(vaultFile()), master())) {
            EncryptedSyncRecord record = saveLoginAndExport(vault);
            AtomicReference<String> seenPassword = new AtomicReference<>();
            vault.previewSyncRecord(
                    record,
                    preview -> {
                        assertTrue(preview instanceof SyncRecordPreview.Active);
                        SyncRecordPreview.Active active = (SyncRecordPreview.Active) preview;
                        assertEquals("GitHub", active.metadata().title());
                        assertEquals(SecretType.LOGIN_PASSWORD, active.metadata().secretType());
                        assertTrue(active.payload() instanceof SyncPayloadView.Login);
                        ((SyncPayloadView.Login) active.payload())
                                .view()
                                .withPassword(p -> seenPassword.set(new String(p)));
                    });
            assertEquals("secret-password", seenPassword.get());
        }
    }

    @Test
    void previewDecodesDeletedTombstone() {
        VaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        try (VaultHandle vault =
                service.createVault(new CreateVaultRequest(vaultFile()), master())) {
            try (SecretBuffer username = SecretBuffer.fromChars(chars("alice@example.com"));
                    SecretBuffer password = SecretBuffer.fromChars(chars("secret-password"))) {
                vault.saveLogin(
                        draft -> draft.title("GitHub").username(username).password(password));
            }
            vault.deleteSecret(vault.listSecrets().getFirst().secretId());
            EncryptedSyncRecord tombstone = vault.exportRecordsSince(0).getFirst();
            assertTrue(tombstone.deleted());
            AtomicReference<SyncRecordPreview> captured = new AtomicReference<>();
            vault.previewSyncRecord(tombstone, captured::set);
            assertTrue(captured.get() instanceof SyncRecordPreview.Deleted);
            SyncRecordPreview.Deleted deleted = (SyncRecordPreview.Deleted) captured.get();
            assertEquals(SecretType.LOGIN_PASSWORD, deleted.secretType());
            assertTrue(deleted.revision() > 0);
        }
    }

    @Test
    void previewRejectsForeignVaultRecord() {
        VaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        try (VaultHandle vaultA =
                        service.createVault(
                                new CreateVaultRequest(tempDir.resolve("a.kv")), master());
                VaultHandle vaultB =
                        service.createVault(
                                new CreateVaultRequest(tempDir.resolve("b.kv")), master())) {
            EncryptedSyncRecord foreignRecord = saveLoginAndExport(vaultA);
            assertThrows(
                    ValidationException.class,
                    () -> vaultB.previewSyncRecord(foreignRecord, preview -> {}));
        }
    }
}
