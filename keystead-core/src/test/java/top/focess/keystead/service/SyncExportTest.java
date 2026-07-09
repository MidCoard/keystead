package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.model.EncryptedEnvelope;
import top.focess.keystead.model.EncryptedSecretRecord;
import top.focess.keystead.model.KeyId;
import top.focess.keystead.model.SecretClassification;
import top.focess.keystead.model.SecretId;
import top.focess.keystead.model.SecretMetadata;
import top.focess.keystead.model.SecretType;
import top.focess.keystead.model.VaultId;
import top.focess.keystead.store.FileVaultStore;

class SyncExportTest {

    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-07-03T00:00:00Z"), ZoneOffset.UTC);
    private static final VaultId VAULT_ID =
            new VaultId(UUID.fromString("60000000-0000-0000-0000-000000000001"));

    @TempDir Path tempDir;

    @Test
    void exportsEncryptedRecordsWithoutServerVisibleProfileOrAad() {
        VaultService service = new DefaultVaultService(new FileVaultStore(tempDir), CLOCK);
        try (VaultHandle vault = service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
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

            assertEquals(VAULT_ID.value().toString(), record.vaultId());
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
        VaultService service = new DefaultVaultService(new FileVaultStore(tempDir), CLOCK);
        try (VaultHandle vault = service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
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
        VaultService service = new DefaultVaultService(new FileVaultStore(tempDir), CLOCK);
        try (VaultHandle vault = service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
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
    void exportRecordsSinceOrdersByRevisionThenSecretId() {
        FileVaultStore store = new FileVaultStore(tempDir);
        VaultService service = new DefaultVaultService(store, CLOCK);
        try (VaultHandle vault = service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
            SecretId firstRevisionHighId = new SecretId(new UUID(0L, 99L));
            SecretId secondRevisionLowId = new SecretId(new UUID(0L, 2L));
            store.saveSecretRecord(storedRecord(firstRevisionHighId, 1L));
            store.saveSecretRecord(storedRecord(secondRevisionLowId, 2L));

            List<String> exportedSecretIds =
                    vault.exportRecordsSince(0).stream()
                            .map(EncryptedSyncRecord::secretId)
                            .toList();

            assertEquals(
                    List.of(
                            firstRevisionHighId.value().toString(),
                            secondRevisionLowId.value().toString()),
                    exportedSecretIds);
        }
    }

    @Test
    void importsEncryptedRecordAndReconstructsLocalAad() {
        FileVaultStore store = new FileVaultStore(tempDir);
        VaultService service = new DefaultVaultService(store, CLOCK);
        try (VaultHandle vault = service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
            try (SecretBuffer value = SecretBuffer.fromChars(chars("ghp_secret"))) {
                vault.saveSecret(
                        SecretType.API_TOKEN,
                        draft ->
                                draft.title("GitHub token")
                                        .classification(
                                                new SecretClassification(
                                                        "development",
                                                        "github",
                                                        "github.com",
                                                        "alice@example.com"))
                                        .field("token", value));
            }

            EncryptedSyncRecord exported = vault.exportRecordsSince(0).getFirst();
            store.deleteSecretRecord(VAULT_ID, new SecretId(UUID.fromString(exported.secretId())));
            assertTrue(vault.listSecrets().isEmpty());

            assertEquals(1, vault.importRecords(List.of(exported)));

            assertEquals("GitHub token", vault.listSecrets().getFirst().title());
            assertEquals("github.com", vault.listSecrets().getFirst().classification().software());
            vault.withSecret(
                    new top.focess.keystead.model.SecretId(UUID.fromString(exported.secretId())),
                    view ->
                            view.withField(
                                    "token",
                                    chars -> assertEquals("ghp_secret", new String(chars))));
        }
    }

    @Test
    void deleteExportsDurableTombstoneAndRejectsOlderRecordResurrection() {
        VaultService service = new DefaultVaultService(new FileVaultStore(tempDir), CLOCK);
        EncryptedSyncRecord original;
        try (VaultHandle vault = service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
            try (SecretBuffer value = SecretBuffer.fromChars(chars("ghp_secret"))) {
                vault.saveSecret(
                        SecretType.API_TOKEN,
                        draft -> draft.title("GitHub token").field("token", value));
            }
            original = vault.exportRecordsSince(0).getFirst();

            vault.deleteSecret(new SecretId(UUID.fromString(original.secretId())));
        }

        try (VaultHandle vault = service.openVault(VAULT_ID, master())) {
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
        VaultService service = new DefaultVaultService(new FileVaultStore(tempDir), CLOCK);
        try (VaultHandle vault = service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
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
        FileVaultStore store = new FileVaultStore(tempDir);
        VaultService service = new DefaultVaultService(store, CLOCK);
        try (VaultHandle vault = service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
            try (SecretBuffer value = SecretBuffer.fromChars(chars("ghp_secret"))) {
                vault.saveSecret(
                        SecretType.API_TOKEN,
                        draft -> draft.title("GitHub token").field("token", value));
            }
            EncryptedSyncRecord valid = vault.exportRecordsSince(0).getFirst();
            SecretId validSecretId = new SecretId(UUID.fromString(valid.secretId()));
            store.deleteSecretRecord(VAULT_ID, validSecretId);
            EncryptedSyncRecord foreign =
                    new EncryptedSyncRecord(
                            new VaultId(UUID.fromString("60000000-0000-0000-0000-000000000099"))
                                    .value()
                                    .toString(),
                            UUID.randomUUID().toString(),
                            2L,
                            SecretType.API_TOKEN.name(),
                            "",
                            "",
                            true);

            assertThrows(
                    ValidationException.class,
                    () -> vault.importRecordsWithReport(List.of(valid, foreign)));

            assertTrue(vault.listSecrets().isEmpty());
            assertEquals(0, vault.exportRecordsSince(0).size());
        }
    }

    @Test
    void importRejectsMalformedBatchBeforeWritingAnyRows() {
        FileVaultStore store = new FileVaultStore(tempDir);
        VaultService service = new DefaultVaultService(store, CLOCK);
        try (VaultHandle vault = service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
            try (SecretBuffer value = SecretBuffer.fromChars(chars("ghp_secret"))) {
                vault.saveSecret(
                        SecretType.API_TOKEN,
                        draft -> draft.title("GitHub token").field("token", value));
            }
            EncryptedSyncRecord valid = vault.exportRecordsSince(0).getFirst();
            SecretId validSecretId = new SecretId(UUID.fromString(valid.secretId()));
            store.deleteSecretRecord(VAULT_ID, validSecretId);
            EncryptedSyncRecord malformed =
                    new EncryptedSyncRecord(
                            VAULT_ID.value().toString(),
                            "not-a-secret-id",
                            2L,
                            SecretType.API_TOKEN.name(),
                            "",
                            "",
                            true);

            assertThrows(
                    ValidationException.class,
                    () -> vault.importRecordsWithReport(List.of(valid, malformed)));

            assertTrue(vault.listSecrets().isEmpty());
            assertEquals(0, vault.exportRecordsSince(0).size());
        }
    }

    @Test
    void importRejectsUndecodableActiveBatchBeforeWritingAnyRows() {
        FileVaultStore store = new FileVaultStore(tempDir);
        VaultService service = new DefaultVaultService(store, CLOCK);
        try (VaultHandle vault = service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
            try (SecretBuffer value = SecretBuffer.fromChars(chars("ghp_secret"))) {
                vault.saveSecret(
                        SecretType.API_TOKEN,
                        draft -> draft.title("GitHub token").field("token", value));
            }
            EncryptedSyncRecord valid = vault.exportRecordsSince(0).getFirst();
            SecretId validSecretId = new SecretId(UUID.fromString(valid.secretId()));
            store.deleteSecretRecord(VAULT_ID, validSecretId);
            EncryptedSyncRecord undecodable =
                    new EncryptedSyncRecord(
                            VAULT_ID.value().toString(),
                            UUID.randomUUID().toString(),
                            2L,
                            SecretType.API_TOKEN.name(),
                            "not-an-envelope",
                            "not-an-envelope",
                            false);

            assertThrows(
                    ValidationException.class,
                    () -> vault.importRecordsWithReport(List.of(valid, undecodable)));

            assertTrue(vault.listSecrets().isEmpty());
            assertEquals(0, vault.exportRecordsSince(0).size());
        }
    }

    @Test
    void importRejectsUndecryptablePayloadBatchBeforeWritingAnyRows() {
        FileVaultStore store = new FileVaultStore(tempDir);
        VaultService service = new DefaultVaultService(store, CLOCK);
        try (VaultHandle vault = service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
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
            store.deleteSecretRecord(VAULT_ID, new SecretId(UUID.fromString(valid.secretId())));
            store.deleteSecretRecord(
                    VAULT_ID, new SecretId(UUID.fromString(corruptBase.secretId())));
            EncryptedSyncRecord corrupt =
                    new EncryptedSyncRecord(
                            corruptBase.vaultId(),
                            corruptBase.secretId(),
                            corruptBase.revision(),
                            corruptBase.secretType(),
                            corruptBase.encryptedProfile(),
                            tamperedCiphertextEnvelope(corruptBase.envelope()),
                            false);

            assertThrows(
                    ValidationException.class,
                    () -> vault.importRecordsWithReport(List.of(valid, corrupt)));

            assertTrue(vault.listSecrets().isEmpty());
            assertEquals(0, vault.exportRecordsSince(0).size());
        }
    }

    @Test
    void importRejectsDuplicateSecretBatchBeforeWritingAnyRows() {
        FileVaultStore store = new FileVaultStore(tempDir);
        VaultService service = new DefaultVaultService(store, CLOCK);
        try (VaultHandle vault = service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
            try (SecretBuffer value = SecretBuffer.fromChars(chars("ghp_secret"))) {
                vault.saveSecret(
                        SecretType.API_TOKEN,
                        draft -> draft.title("GitHub token").field("token", value));
            }
            EncryptedSyncRecord valid = vault.exportRecordsSince(0).getFirst();
            SecretId validSecretId = new SecretId(UUID.fromString(valid.secretId()));
            store.deleteSecretRecord(VAULT_ID, validSecretId);
            EncryptedSyncRecord duplicateTombstone =
                    new EncryptedSyncRecord(
                            VAULT_ID.value().toString(),
                            valid.secretId(),
                            valid.revision() + 1,
                            SecretType.API_TOKEN.name(),
                            "",
                            "",
                            true);

            assertThrows(
                    ValidationException.class,
                    () -> vault.importRecordsWithReport(List.of(valid, duplicateTombstone)));

            assertTrue(vault.listSecrets().isEmpty());
            assertEquals(0, vault.exportRecordsSince(0).size());
        }
    }

    @Test
    void importReportPreservesConflictWhenRemoteTombstoneIsOlderThanLocalUpdate() {
        VaultService service = new DefaultVaultService(new FileVaultStore(tempDir), CLOCK);
        try (VaultHandle vault = service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
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
                            VAULT_ID.value().toString(),
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
                                VAULT_ID.value().toString(),
                                UUID.randomUUID().toString(),
                                0L,
                                SecretType.API_TOKEN.name(),
                                "profile",
                                "envelope",
                                false));
    }

    @Test
    void activeSyncRecordRejectsMissingEncryptedProfileOrEnvelope() {
        String vaultId = VAULT_ID.value().toString();
        String secretId = UUID.randomUUID().toString();

        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new EncryptedSyncRecord(
                                vaultId,
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
                                vaultId,
                                secretId,
                                1L,
                                SecretType.API_TOKEN.name(),
                                "profile",
                                "",
                                false));
    }

    @Test
    void deletedSyncRecordRejectsEncryptedProfileOrEnvelope() {
        String vaultId = VAULT_ID.value().toString();
        String secretId = UUID.randomUUID().toString();

        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new EncryptedSyncRecord(
                                vaultId,
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
                                vaultId,
                                secretId,
                                1L,
                                SecretType.API_TOKEN.name(),
                                "",
                                "payload",
                                true));
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

    private static EncryptedSecretRecord storedRecord(@NonNull SecretId secretId, long revision) {
        SecretMetadata metadata =
                new SecretMetadata(
                        secretId,
                        SecretType.API_TOKEN,
                        "stored-" + revision,
                        Set.of(),
                        CLOCK.instant(),
                        CLOCK.instant(),
                        revision);
        return new EncryptedSecretRecord(VAULT_ID, metadata, envelope(revision), revision);
    }

    private static EncryptedEnvelope envelope(long revision) {
        return new EncryptedEnvelope(
                1,
                "test",
                new KeyId("test-key"),
                new byte[] {(byte) revision},
                new byte[0],
                new byte[] {(byte) (revision + 1)},
                CLOCK.instant());
    }
}
