package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.*;

import java.io.*;
import java.nio.file.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ReviewRegressionTest {
    @TempDir Path temp;

    char[] pw() {
        return "review-password-only".toCharArray();
    }

    @Test
    void restoreDoesNotOverwriteTargetCreatedDuringArchiveRead() throws Exception {
        var service = new DefaultVaultService();
        var backups = new FullVaultBackupService();
        var output = new ByteArrayOutputStream();
        try (var source = service.createVault(temp.resolve("source"), pw())) {
            backups.export(source, pw(), output);
        }
        Path target = temp.resolve("target");
        byte[] important = "existing important vault data".getBytes();
        InputStream input =
                new FilterInputStream(new ByteArrayInputStream(output.toByteArray())) {
                    boolean created;

                    void create() throws IOException {
                        if (!created) {
                            Files.write(target, important);
                            created = true;
                        }
                    }

                    @Override
                    public int read() throws IOException {
                        create();
                        return super.read();
                    }

                    @Override
                    public int read(byte[] b, int o, int l) throws IOException {
                        create();
                        return super.read(b, o, l);
                    }
                };
        assertThrows(ValidationException.class, () -> backups.restore(target, input, pw(), pw()));
        assertArrayEquals(
                important,
                Files.readAllBytes(target),
                "Restore silently replaced target created after precheck");
    }

    @Test
    void symlinkCannotBypassOpenVaultLock() throws Exception {
        var service = new DefaultVaultService();
        Path actual = temp.resolve("actual"), alias = temp.resolve("alias");
        try (var first = service.createVault(actual, pw())) {
            Files.createSymbolicLink(alias, actual);
            assertThrows(
                    top.focess.keystead.store.StoreException.class,
                    () -> service.openVault(alias, pw()));
            assertTrue(Files.isSymbolicLink(alias));
            assertEquals(0, first.listSecrets().size());
        }
        assertThrows(
                top.focess.keystead.store.StoreException.class,
                () -> service.openVault(alias, pw()));
    }

    @Test
    void successfullyStoredLargeRecordCanBeBackedUp() throws Exception {
        Path path = temp.resolve("large");
        var service = new DefaultVaultService();
        try (var vault = service.createVault(path, pw());
                var body = top.focess.keystead.memory.SecretBuffer.fromUtf8(new byte[800_000])) {
            vault.saveSecret(
                    top.focess.keystead.model.SecretType.GENERIC_SECRET,
                    d -> d.title("large secret").field("value", body));
        }
        try (var reopened = service.openVault(path, pw())) {
            assertEquals(1, reopened.listSecrets().size());
            var output = new ByteArrayOutputStream();
            var backups = new FullVaultBackupService();
            assertDoesNotThrow(() -> backups.export(reopened, pw(), output));
            try (var restored =
                    backups.restore(
                            temp.resolve("restored-large"),
                            new ByteArrayInputStream(output.toByteArray()),
                            pw(),
                            pw())) {
                var id = restored.listSecrets().getFirst().secretId();
                restored.withSecret(
                        id,
                        view ->
                                view.withField(
                                        "value", chars -> assertEquals(800_000, chars.length)));
            }
        }
    }

    @Test
    void malformedEnvelopeTimestampIsRejectedWithoutAbortingBatch() throws Exception {
        try (var vault = new DefaultVaultService().createVault(temp.resolve("timestamps"), pw());
                var body =
                        top.focess.keystead.memory.SecretBuffer.fromChars(
                                "fixture".toCharArray())) {
            vault.saveSecureNote(d -> d.title("note").body(body));
            var row = vault.exportRecordsSince(0).getFirst();
            String badProfile =
                    row.encryptedProfile()
                            .replaceFirst("encryptedAt=[^\\r\\n]*", "encryptedAt=not-a-date");
            assertNotEquals(row.encryptedProfile(), badProfile);
            var bad =
                    new EncryptedSyncRecord(
                            row.fingerprint(),
                            row.secretId(),
                            row.revision(),
                            row.secretType(),
                            badProfile,
                            row.envelope(),
                            row.deleted(),
                            row.contentKey());
            var report =
                    assertDoesNotThrow(() -> vault.importRecordsWithReport(java.util.List.of(bad)));
            assertEquals(1, report.rejected().size());
        }
    }
}
