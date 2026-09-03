package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Properties;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.model.SecretId;
import top.focess.keystead.model.SecretType;

class TolerantSyncImportTest {

    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-08-02T00:00:00Z"), ZoneOffset.UTC);

    @TempDir Path directory;

    @Test
    void validRecordIsImportedWhileAnUndecryptableRecordIsRejected() throws IOException {
        VaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        Path sourceFile = directory.resolve("source.kvault");
        Path targetFile = directory.resolve("target.kvault");
        createOneRecord(service, sourceFile);
        Files.copy(sourceFile, targetFile);

        EncryptedSyncRecord valid;
        try (VaultHandle source = service.openVault(sourceFile, master());
                SecretBuffer value = SecretBuffer.fromChars("second".toCharArray())) {
            source.saveSecret(
                    SecretType.API_TOKEN, draft -> draft.title("Second").field("token", value));
            valid = source.exportRecordsSince(1).getFirst();
        }
        EncryptedSyncRecord corrupt =
                new EncryptedSyncRecord(
                        valid.fingerprint(),
                        UUID.randomUUID().toString(),
                        valid.revision() + 1,
                        valid.secretType(),
                        "not-an-envelope",
                        "not-an-envelope",
                        false,
                        "content-key");

        try (VaultHandle target = service.openVault(targetFile, master())) {
            SyncImportReport report = target.importRecordsWithReport(List.of(valid, corrupt));

            assertEquals(1, report.imported());
            assertEquals(1, report.rejected().size());
            assertEquals(corrupt.secretId(), report.rejected().getFirst().secretId());
            assertEquals(2, target.listSecrets().size());
        }
    }

    @Test
    void tamperedTombstoneCannotDeleteALocalRecord() throws IOException {
        VaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        Path sourceFile = directory.resolve("delete-source.kvault");
        Path targetFile = directory.resolve("delete-target.kvault");
        SecretId secretId = createOneRecord(service, sourceFile);
        Files.copy(sourceFile, targetFile);

        EncryptedSyncRecord tombstone;
        try (VaultHandle source = service.openVault(sourceFile, master())) {
            source.deleteSecret(secretId);
            tombstone = source.exportRecordsSince(1).getFirst();
        }
        assertFalse(tombstone.encryptedProfile().isEmpty());
        EncryptedSyncRecord tampered =
                new EncryptedSyncRecord(
                        tombstone.fingerprint(),
                        tombstone.secretId(),
                        tombstone.revision(),
                        tombstone.secretType(),
                        tamper(tombstone.encryptedProfile()),
                        "",
                        true,
                        tombstone.contentKey());

        try (VaultHandle target = service.openVault(targetFile, master())) {
            SyncImportReport report = target.importRecordsWithReport(List.of(tampered));

            assertEquals(0, report.imported());
            assertEquals(1, report.rejected().size());
            assertEquals(1, target.listSecrets().size());
        }
    }

    private static SecretId createOneRecord(VaultService service, Path file) {
        try (VaultHandle vault = service.createVault(file, master());
                SecretBuffer value = SecretBuffer.fromChars("first".toCharArray())) {
            return vault.saveSecret(
                    SecretType.API_TOKEN, draft -> draft.title("First").field("token", value));
        }
    }

    private static char[] master() {
        return "correct horse battery staple".toCharArray();
    }

    private static String tamper(String encoded) throws IOException {
        Properties properties = new Properties();
        properties.load(new StringReader(encoded));
        byte[] ciphertext = Base64.getDecoder().decode(properties.getProperty("ciphertext"));
        ciphertext[0] ^= 1;
        properties.setProperty("ciphertext", Base64.getEncoder().encodeToString(ciphertext));
        StringWriter writer = new StringWriter();
        properties.store(writer, "tampered");
        return writer.toString();
    }
}
