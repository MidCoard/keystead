package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.model.SecretClassification;
import top.focess.keystead.model.SecretId;
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
            assertFalse(record.envelope().contains("aad"));
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
                                                        "alice@example.com"))
                                        .field("token", value));
            }

            EncryptedSyncRecord exported = vault.exportRecordsSince(0).getFirst();
            store.deleteSecretRecord(VAULT_ID, new SecretId(UUID.fromString(exported.secretId())));
            assertTrue(vault.listSecrets().isEmpty());

            assertEquals(1, vault.importRecords(List.of(exported)));

            assertEquals("GitHub token", vault.listSecrets().getFirst().title());
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
}
