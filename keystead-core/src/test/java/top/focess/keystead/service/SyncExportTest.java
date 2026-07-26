package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static top.focess.keystead.model.SecurityLimits.MAX_ENCODED_SYNC_CHARACTERS;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.model.SecretClassification;
import top.focess.keystead.model.SecretId;
import top.focess.keystead.model.SecretType;

class SyncExportTest {

    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-07-03T00:00:00Z"), ZoneOffset.UTC);
    private static final String FINGERPRINT = "60000000000000000000000000000001";
    private static final String FOREIGN_FINGERPRINT = "60000000000000000000000000000099";

    @TempDir Path tempDir;

    private Path vaultFile() {
        return tempDir.resolve("vault.kv");
    }

    @Test
    void exportRejectsNegativeSyncCursorBeforeReadingRows() {
        VaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        try (VaultHandle vault =
                service.createVault(new CreateVaultRequest(vaultFile()), master())) {
            ValidationException failure =
                    assertThrows(ValidationException.class, () -> vault.exportRecordsSince(-1));
            assertEquals("Since revision must not be negative", failure.getMessage());
        }
    }

    @Test
    void exportsEncryptedRecordsWithoutServerVisibleProfileOrAad() {
        VaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        try (VaultHandle vault =
                service.createVault(new CreateVaultRequest(vaultFile()), master())) {
            try (SecretBuffer username = SecretBuffer.fromChars(chars("alice@example.com"));
                    SecretBuffer password = SecretBuffer.fromChars(chars("secret-password"))) {
                vault.saveLogin(
                        draft ->
                                draft.title("GitHub")
                                        .classification(
                                                new SecretClassification(
                                                        "development",
                                                        "github",
                                                        "github.com",
                                                        "alice@example.com",
                                                        Set.of("work")))
                                        .username(username)
                                        .password(password));
            }

            EncryptedSyncRecord record = vault.exportRecordsSince(0).getFirst();

            assertEquals(vault.vaultFingerprint().toHexString(), record.fingerprint());
            assertEquals(SecretType.LOGIN_PASSWORD.name(), record.secretType());
            assertEquals(1L, record.revision());
            assertFalse(record.deleted());
            assertFalse(record.encryptedProfile().contains("GitHub"));
            assertFalse(record.encryptedProfile().contains("github"));
            assertFalse(syncEnvelopeProperties(record.envelope()).containsKey("aad"));
            assertFalse(record.envelope().contains(encoded("GitHub")));
        }
    }

    @Test
    void exportRecordsSinceFiltersByRevision() {
        VaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        try (VaultHandle vault =
                service.createVault(new CreateVaultRequest(vaultFile()), master())) {
            try (SecretBuffer value = SecretBuffer.fromChars(chars("token"))) {
                vault.saveSecret(
                        SecretType.API_TOKEN, draft -> draft.title("Token").field("token", value));
            }

            assertEquals(1, vault.exportRecordsSince(0).size());
            assertEquals(0, vault.exportRecordsSince(1).size());
        }
    }

    @Test
    void newSecretsUseVaultWideRevisionSoSinceCursorDoesNotSkipThem() {
        VaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        try (VaultHandle vault =
                service.createVault(new CreateVaultRequest(vaultFile()), master())) {
            try (SecretBuffer value = SecretBuffer.fromChars(chars("first"))) {
                vault.saveSecret(
                        SecretType.API_TOKEN,
                        draft -> draft.title("First token").field("token", value));
            }

            EncryptedSyncRecord first = vault.exportRecordsSince(0).getFirst();
            assertEquals(1L, first.revision());

            try (SecretBuffer value = SecretBuffer.fromChars(chars("second"))) {
                vault.saveSecret(
                        SecretType.API_TOKEN,
                        draft -> draft.title("Second token").field("token", value));
            }

            List<EncryptedSyncRecord> records = vault.exportRecordsSince(first.revision());

            assertEquals(1, records.size());
            assertEquals(2L, records.getFirst().revision());
            assertEquals("Second token", encryptedProfileTitle(vault, records.getFirst()));
        }
    }

    @Test
    void deleteExportsDurableTombstoneAndRejectsOlderRecordResurrection() {
        VaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        EncryptedSyncRecord original;
        try (VaultHandle vault =
                service.createVault(new CreateVaultRequest(vaultFile()), master())) {
            try (SecretBuffer value = SecretBuffer.fromChars(chars("ghp_secret"))) {
                vault.saveSecret(
                        SecretType.API_TOKEN,
                        draft -> draft.title("GitHub token").field("token", value));
            }
            original = vault.exportRecordsSince(0).getFirst();

            vault.deleteSecret(new SecretId(UUID.fromString(original.secretId())));
        }

        try (VaultHandle vault = service.openVault(vaultFile(), master())) {
            EncryptedSyncRecord tombstone = vault.exportRecordsSince(1).getFirst();

            assertEquals(original.secretId(), tombstone.secretId());
            assertEquals(2L, tombstone.revision());
            assertEquals(SecretType.API_TOKEN.name(), tombstone.secretType());
            assertTrue(tombstone.deleted());
            assertEquals("", tombstone.encryptedProfile());
            assertEquals("", tombstone.envelope());
            assertEquals(0, vault.importRecords(List.of(original)));
            assertTrue(vault.listSecrets().isEmpty());
        }
    }

    @Test
    void importSkipsOlderServerRevision() {
        VaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        try (VaultHandle vault =
                service.createVault(new CreateVaultRequest(vaultFile()), master())) {
            try (SecretBuffer value = SecretBuffer.fromChars(chars("ghp_secret"))) {
                vault.saveSecret(
                        SecretType.API_TOKEN,
                        draft -> draft.title("GitHub token").field("token", value));
            }

            EncryptedSyncRecord exported = vault.exportRecordsSince(0).getFirst();

            assertEquals(0, vault.importRecords(List.of(exported)));
        }
    }

    @Test
    void importRejectsMixedVaultBatchBeforeWritingAnyRows() {
        VaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        try (VaultHandle vault =
                service.createVault(new CreateVaultRequest(vaultFile()), master())) {
            try (SecretBuffer value = SecretBuffer.fromChars(chars("ghp_secret"))) {
                vault.saveSecret(
                        SecretType.API_TOKEN,
                        draft -> draft.title("GitHub token").field("token", value));
            }
            EncryptedSyncRecord valid = vault.exportRecordsSince(0).getFirst();
            EncryptedSyncRecord foreign =
                    new EncryptedSyncRecord(
                            FOREIGN_FINGERPRINT,
                            UUID.randomUUID().toString(),
                            2L,
                            SecretType.API_TOKEN.name(),
                            "",
                            "",
                            true);

            assertEquals(1, vault.listSecrets().size());
            assertThrows(
                    ValidationException.class,
                    () -> vault.importRecordsWithReport(List.of(valid, foreign)));

            assertEquals(1, vault.listSecrets().size());
            assertEquals(1, vault.exportRecordsSince(0).size());
        }
    }

    @Test
    void importRejectsMalformedBatchBeforeWritingAnyRows() {
        VaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        try (VaultHandle vault =
                service.createVault(new CreateVaultRequest(vaultFile()), master())) {
            try (SecretBuffer value = SecretBuffer.fromChars(chars("ghp_secret"))) {
                vault.saveSecret(
                        SecretType.API_TOKEN,
                        draft -> draft.title("GitHub token").field("token", value));
            }
            EncryptedSyncRecord valid = vault.exportRecordsSince(0).getFirst();
            EncryptedSyncRecord malformed =
                    new EncryptedSyncRecord(
                            vault.vaultFingerprint().toHexString(),
                            "not-a-secret-id",
                            2L,
                            SecretType.API_TOKEN.name(),
                            "",
                            "",
                            true);

            assertEquals(1, vault.listSecrets().size());
            assertThrows(
                    ValidationException.class,
                    () -> vault.importRecordsWithReport(List.of(valid, malformed)));

            assertEquals(1, vault.listSecrets().size());
            assertEquals(1, vault.exportRecordsSince(0).size());
        }
    }

    @Test
    void importRejectsUndecodableActiveBatchBeforeWritingAnyRows() {
        VaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        try (VaultHandle vault =
                service.createVault(new CreateVaultRequest(vaultFile()), master())) {
            try (SecretBuffer value = SecretBuffer.fromChars(chars("ghp_secret"))) {
                vault.saveSecret(
                        SecretType.API_TOKEN,
                        draft -> draft.title("GitHub token").field("token", value));
            }
            EncryptedSyncRecord valid = vault.exportRecordsSince(0).getFirst();
            EncryptedSyncRecord undecodable =
                    new EncryptedSyncRecord(
                            vault.vaultFingerprint().toHexString(),
                            UUID.randomUUID().toString(),
                            2L,
                            SecretType.API_TOKEN.name(),
                            "not-an-envelope",
                            "not-an-envelope",
                            false);

            assertEquals(1, vault.listSecrets().size());
            assertThrows(
                    ValidationException.class,
                    () -> vault.importRecordsWithReport(List.of(valid, undecodable)));

            assertEquals(1, vault.listSecrets().size());
            assertEquals(1, vault.exportRecordsSince(0).size());
        }
    }

    @Test
    void importRejectsUndecryptablePayloadBatchBeforeWritingAnyRows() {
        VaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        try (VaultHandle vault =
                service.createVault(new CreateVaultRequest(vaultFile()), master())) {
            try (SecretBuffer value = SecretBuffer.fromChars(chars("ghp_secret_one"))) {
                vault.saveSecret(
                        SecretType.API_TOKEN,
                        draft -> draft.title("GitHub token one").field("token", value));
            }
            try (SecretBuffer value = SecretBuffer.fromChars(chars("ghp_secret_two"))) {
                vault.saveSecret(
                        SecretType.API_TOKEN,
                        draft -> draft.title("GitHub token two").field("token", value));
            }
            List<EncryptedSyncRecord> exported = vault.exportRecordsSince(0);
            EncryptedSyncRecord valid = exported.get(0);
            EncryptedSyncRecord corruptBase = exported.get(1);
            EncryptedSyncRecord corrupt =
                    new EncryptedSyncRecord(
                            corruptBase.fingerprint(),
                            corruptBase.secretId(),
                            corruptBase.revision(),
                            corruptBase.secretType(),
                            corruptBase.encryptedProfile(),
                            tamperedCiphertextEnvelope(corruptBase.envelope()),
                            false);

            assertEquals(2, vault.listSecrets().size());
            assertThrows(
                    ValidationException.class,
                    () -> vault.importRecordsWithReport(List.of(valid, corrupt)));

            assertEquals(2, vault.listSecrets().size());
            assertEquals(2, vault.exportRecordsSince(0).size());
        }
    }

    @Test
    void importRejectsDuplicateSecretBatchBeforeWritingAnyRows() {
        VaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        try (VaultHandle vault =
                service.createVault(new CreateVaultRequest(vaultFile()), master())) {
            try (SecretBuffer value = SecretBuffer.fromChars(chars("ghp_secret"))) {
                vault.saveSecret(
                        SecretType.API_TOKEN,
                        draft -> draft.title("GitHub token").field("token", value));
            }
            EncryptedSyncRecord valid = vault.exportRecordsSince(0).getFirst();
            EncryptedSyncRecord duplicateTombstone =
                    new EncryptedSyncRecord(
                            vault.vaultFingerprint().toHexString(),
                            valid.secretId(),
                            valid.revision() + 1,
                            SecretType.API_TOKEN.name(),
                            "",
                            "",
                            true);

            assertEquals(1, vault.listSecrets().size());
            assertThrows(
                    ValidationException.class,
                    () -> vault.importRecordsWithReport(List.of(valid, duplicateTombstone)));

            assertEquals(1, vault.listSecrets().size());
            assertEquals(1, vault.exportRecordsSince(0).size());
        }
    }

    @Test
    void importReportPreservesConflictWhenRemoteTombstoneIsOlderThanLocalUpdate() {
        VaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        try (VaultHandle vault =
                service.createVault(new CreateVaultRequest(vaultFile()), master())) {
            SecretId secretId;
            try (SecretBuffer value = SecretBuffer.fromChars(chars("first"))) {
                secretId =
                        vault.saveSecret(
                                SecretType.API_TOKEN,
                                draft -> draft.title("Token").field("token", value));
            }
            try (SecretBuffer value = SecretBuffer.fromChars(chars("second"))) {
                vault.updateSecret(secretId, draft -> draft.title("Token").field("token", value));
            }

            EncryptedSyncRecord staleTombstone =
                    new EncryptedSyncRecord(
                            vault.vaultFingerprint().toHexString(),
                            secretId.value().toString(),
                            1L,
                            SecretType.API_TOKEN.name(),
                            "",
                            "",
                            true);
            SyncImportReport report = vault.importRecordsWithReport(List.of(staleTombstone));

            assertEquals(0, report.imported());
            assertEquals(0, report.skipped());
            assertEquals(1, report.conflicts().size());
            SyncImportConflict conflict = report.conflicts().getFirst();
            assertEquals(secretId.value().toString(), conflict.secretId());
            assertEquals(2L, conflict.localRevision());
            assertEquals(1L, conflict.remoteRevision());
            assertFalse(conflict.localDeleted());
            assertTrue(conflict.remoteDeleted());
            assertEquals(1, vault.listSecrets().size());
        }
    }

    @Test
    void syncRecordRejectsZeroRevisionBecauseCommittedRowsStartAtOne() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new EncryptedSyncRecord(
                                FINGERPRINT,
                                UUID.randomUUID().toString(),
                                0L,
                                SecretType.API_TOKEN.name(),
                                "profile",
                                "envelope",
                                false));
    }

    @Test
    void syncRecordRejectsBlankIdentityAndSecretType() {
        String fingerprint = FINGERPRINT;
        String secretId = UUID.randomUUID().toString();

        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new EncryptedSyncRecord(
                                " ",
                                secretId,
                                1L,
                                SecretType.API_TOKEN.name(),
                                "profile",
                                "envelope",
                                false));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new EncryptedSyncRecord(
                                fingerprint,
                                " ",
                                1L,
                                SecretType.API_TOKEN.name(),
                                "profile",
                                "envelope",
                                false));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new EncryptedSyncRecord(
                                fingerprint, secretId, 1L, " ", "profile", "envelope", false));
    }

    @Test
    void syncRecordRejectsUnsupportedSecretType() {
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new EncryptedSyncRecord(
                                FINGERPRINT,
                                UUID.randomUUID().toString(),
                                1L,
                                "OAUTH_REFRESH_TOKEN",
                                "profile",
                                "envelope",
                                false));
    }

    @Test
    void activeSyncRecordRejectsMissingEncryptedProfileOrEnvelope() {
        String fingerprint = FINGERPRINT;
        String secretId = UUID.randomUUID().toString();

        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new EncryptedSyncRecord(
                                fingerprint,
                                secretId,
                                1L,
                                SecretType.API_TOKEN.name(),
                                "",
                                "payload",
                                false));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new EncryptedSyncRecord(
                                fingerprint,
                                secretId,
                                1L,
                                SecretType.API_TOKEN.name(),
                                "profile",
                                "",
                                false));
    }

    @Test
    void deletedSyncRecordRejectsEncryptedProfileOrEnvelope() {
        String fingerprint = FINGERPRINT;
        String secretId = UUID.randomUUID().toString();

        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new EncryptedSyncRecord(
                                fingerprint,
                                secretId,
                                1L,
                                SecretType.API_TOKEN.name(),
                                "profile",
                                "",
                                true));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new EncryptedSyncRecord(
                                fingerprint,
                                secretId,
                                1L,
                                SecretType.API_TOKEN.name(),
                                "",
                                "payload",
                                true));
    }

    @Test
    void activeSyncRecordEnforcesEncodedFieldLimits() {
        String exact = "x".repeat(MAX_ENCODED_SYNC_CHARACTERS);
        EncryptedSyncRecord record =
                new EncryptedSyncRecord(
                        FINGERPRINT,
                        UUID.randomUUID().toString(),
                        1L,
                        SecretType.API_TOKEN.name(),
                        exact,
                        exact,
                        false);

        assertEquals(MAX_ENCODED_SYNC_CHARACTERS, record.encryptedProfile().length());
        assertEquals(MAX_ENCODED_SYNC_CHARACTERS, record.envelope().length());
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new EncryptedSyncRecord(
                                FINGERPRINT,
                                UUID.randomUUID().toString(),
                                1L,
                                SecretType.API_TOKEN.name(),
                                "x".repeat(MAX_ENCODED_SYNC_CHARACTERS + 1),
                                "envelope",
                                false));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new EncryptedSyncRecord(
                                FINGERPRINT,
                                UUID.randomUUID().toString(),
                                1L,
                                SecretType.API_TOKEN.name(),
                                "profile",
                                "x".repeat(MAX_ENCODED_SYNC_CHARACTERS + 1),
                                false));
    }

    private static char[] master() {
        return chars("correct horse battery staple");
    }

    private static char[] chars(String value) {
        return value.toCharArray();
    }

    private static String encoded(String value) {
        return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String encryptedProfileTitle(VaultHandle vault, EncryptedSyncRecord record) {
        SecretId id = new SecretId(UUID.fromString(record.secretId()));
        return vault.listSecrets().stream()
                .filter(metadata -> metadata.id().equals(id))
                .findFirst()
                .orElseThrow()
                .title();
    }

    private static Properties syncEnvelopeProperties(String encoded) {
        try {
            Properties properties = new Properties();
            properties.load(new StringReader(encoded));
            return properties;
        } catch (IOException e) {
            throw new AssertionError("Sync envelope should be Java properties", e);
        }
    }

    private static String tamperedCiphertextEnvelope(String encoded) {
        Properties properties = syncEnvelopeProperties(encoded);
        byte[] ciphertext = Base64.getDecoder().decode(properties.getProperty("ciphertext"));
        ciphertext[0] = (byte) (ciphertext[0] ^ 1);
        properties.setProperty("ciphertext", Base64.getEncoder().encodeToString(ciphertext));
        try {
            StringWriter writer = new StringWriter();
            properties.store(writer, "Keystead sync v1");
            return writer.toString();
        } catch (IOException e) {
            throw new AssertionError("Sync envelope should be writable", e);
        }
    }
}
