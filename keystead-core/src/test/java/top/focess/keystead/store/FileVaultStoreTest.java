package top.focess.keystead.store;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import top.focess.keystead.model.*;

class FileVaultStoreTest {

    @TempDir Path tempDir;

    @Test
    void savesAndLoadsVaultHeader() {
        VaultStore store = new FileVaultStore(tempDir);
        VaultHeader header = header();

        store.saveVaultHeader(header);

        assertEquals(Optional.of(header), store.loadVaultHeader(header.vaultId()));
    }

    @Test
    void savesAndLoadsEncryptedSecretRecord() {
        VaultStore store = new FileVaultStore(tempDir);
        EncryptedSecretRecord record = record();

        store.saveSecretRecord(record);

        assertEquals(
                Optional.of(record),
                store.loadSecretRecord(record.vaultId(), record.metadata().id()));
    }

    @Test
    void savesAndLoadsSecretClassificationMetadata() {
        VaultStore store = new FileVaultStore(tempDir);
        EncryptedSecretRecord record = record();

        store.saveSecretRecord(record);

        SecretMetadata metadata =
                store.loadSecretRecord(record.vaultId(), record.metadata().id())
                        .orElseThrow()
                        .metadata();
        assertEquals("development", metadata.classification().category());
        assertEquals("github", metadata.classification().provider());
        assertEquals("alice@example.com", metadata.classification().account());
        assertEquals(Set.of("work"), metadata.classification().labels());
        assertEquals(Map.of("project", "keystead"), metadata.profile().attributes());
    }

    @Test
    void listsMetadataWithoutOpeningPayload() {
        VaultStore store = new FileVaultStore(tempDir);
        EncryptedSecretRecord record = record();

        store.saveSecretRecord(record);

        assertEquals(List.of(record.metadata()), store.listMetadata(record.vaultId()));
    }

    @Test
    void deleteSecretRecordRemovesPersistedRecord() {
        VaultStore store = new FileVaultStore(tempDir);
        EncryptedSecretRecord record = record();

        store.saveSecretRecord(record);
        store.deleteSecretRecord(record.vaultId(), record.metadata().id());

        assertEquals(
                Optional.empty(), store.loadSecretRecord(record.vaultId(), record.metadata().id()));
        assertEquals(List.of(), store.listMetadata(record.vaultId()));
    }

    @Test
    void secretRecordFileDoesNotContainPlaintextSecretValues() throws IOException {
        VaultStore store = new FileVaultStore(tempDir);
        EncryptedSecretRecord record = record();

        store.saveSecretRecord(record);

        String file =
                Files.readString(
                        tempDir.resolve("secrets")
                                .resolve(record.metadata().id().value() + ".properties"));
        assertFalse(file.contains("alice@example.com"));
        assertFalse(file.contains("secret-password"));
        assertFalse(file.contains("private note"));
    }

    private static VaultHeader header() {
        return new VaultHeader(
                new VaultId(UUID.fromString("00000000-0000-0000-0000-000000000001")),
                1,
                "PBKDF2WithHmacSHA256",
                new byte[] {1, 2, 3},
                120_000,
                new KeyId("vault-key"),
                new byte[] {4, 5, 6},
                Instant.parse("2026-07-02T00:00:00Z"),
                Instant.parse("2026-07-02T00:01:00Z"));
    }

    private static EncryptedSecretRecord record() {
        SecretMetadata metadata =
                new SecretMetadata(
                        new SecretId(UUID.fromString("00000000-0000-0000-0000-000000000002")),
                        SecretType.LOGIN_PASSWORD,
                        new SecretProfile(
                                "GitHub",
                                new SecretClassification(
                                        "development",
                                        "github",
                                        "alice@example.com",
                                        Set.of("work")),
                                Set.of("work", "code"),
                                Map.of("project", "keystead")),
                        Instant.parse("2026-07-02T00:00:00Z"),
                        Instant.parse("2026-07-02T00:01:00Z"),
                        1L);
        EncryptedEnvelope envelope =
                new EncryptedEnvelope(
                        1,
                        "AES-256-GCM",
                        new KeyId("vault-key"),
                        new byte[] {1, 2, 3},
                        new byte[] {4, 5, 6},
                        new byte[] {7, 8, 9},
                        Instant.parse("2026-07-02T00:02:00Z"));
        return new EncryptedSecretRecord(
                new VaultId(UUID.fromString("00000000-0000-0000-0000-000000000001")),
                metadata,
                envelope,
                1L);
    }
}
