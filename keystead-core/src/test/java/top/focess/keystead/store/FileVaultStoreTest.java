package top.focess.keystead.store;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import top.focess.keystead.crypto.KdfParameters;
import top.focess.keystead.model.*;

class FileVaultStoreTest {

    @TempDir Path tempDir;

    @Test
    void rejectsVaultPropertiesLargerThanStoredPropertiesLimit() throws IOException {
        FileVaultStore store = new FileVaultStore(tempDir);
        VaultHeader header = header();
        store.saveVaultHeader(header);
        Path propertiesPath = tempDir.resolve("vault.properties");
        byte[] stored = Files.readAllBytes(propertiesPath);
        byte[] oversized = Arrays.copyOf(stored, SecurityLimits.MAX_STORED_PROPERTIES_BYTES + 1);
        Arrays.fill(oversized, stored.length, oversized.length, (byte) '#');
        Files.write(propertiesPath, oversized);

        StoreException failure =
                assertThrows(StoreException.class, () -> store.loadVaultHeader(header.vaultId()));

        assertEquals("Vault properties exceed the size limit", failure.getMessage());
        assertNull(failure.getCause());
    }

    @Test
    void saveSecretRecordRejectsSecretsDirectorySymlinkWithoutChangingTarget() throws IOException {
        Path vaultDirectory = tempDir.resolve("vault");
        Path outsideDirectory = tempDir.resolve("outside");
        Files.createDirectories(vaultDirectory);
        Files.createDirectories(outsideDirectory);
        Path sentinel = outsideDirectory.resolve("sentinel.txt");
        Files.writeString(sentinel, "unchanged");
        try {
            Files.createSymbolicLink(vaultDirectory.resolve("secrets"), outsideDirectory);
        } catch (IOException | UnsupportedOperationException | SecurityException e) {
            Assumptions.assumeTrue(false, "platform denied symbolic-link creation: " + e);
            return;
        }

        StoreException failure =
                assertThrows(
                        StoreException.class,
                        () -> new FileVaultStore(vaultDirectory).saveSecretRecord(record()));

        assertEquals("Vault path contains a symbolic link", failure.getMessage());
        assertNull(failure.getCause());
        try (var paths = Files.list(outsideDirectory)) {
            assertEquals(
                    List.of("sentinel.txt"),
                    paths.map(Path::getFileName).map(Path::toString).sorted().toList());
        }
        assertEquals("unchanged", Files.readString(sentinel));
    }

    @Test
    void callerSelectedVaultRootMayBeASymbolicLink() throws IOException {
        Path actualDirectory = tempDir.resolve("actual");
        Path linkedDirectory = tempDir.resolve("vault-link");
        Files.createDirectories(actualDirectory);
        try {
            Files.createSymbolicLink(linkedDirectory, actualDirectory);
        } catch (IOException | UnsupportedOperationException | SecurityException e) {
            Assumptions.assumeTrue(false, "platform denied symbolic-link creation: " + e);
            return;
        }
        FileVaultStore store = new FileVaultStore(linkedDirectory);
        VaultHeader header = header();

        store.saveVaultHeader(header);

        assertEquals(Optional.of(header), store.loadVaultHeader(header.vaultId()));
        assertTrue(Files.exists(actualDirectory.resolve("vault.properties")));
    }

    @Test
    void savesAndLoadsVaultHeader() {
        VaultStore store = new FileVaultStore(tempDir);
        VaultHeader header = header();

        store.saveVaultHeader(header);

        assertEquals(Optional.of(header), store.loadVaultHeader(header.vaultId()));
    }

    @Test
    void canonicalGenericKdfHeaderRoundTripsAndKeepsLegacyProperties() throws IOException {
        FileVaultStore store = new FileVaultStore(tempDir);
        VaultHeader header =
                new VaultHeader(
                        new VaultId(UUID.fromString("00000000-0000-0000-0000-000000000001")),
                        1,
                        new KdfParameters(
                                "TEST-KDF",
                                new byte[] {1, 2, 3},
                                Map.of("b", 2, "a", 1, "memoryKiB", 64, "iterations", 3)),
                        new KeyId("vault-key"),
                        new byte[] {4, 5, 6},
                        Instant.parse("2026-07-02T00:00:00Z"),
                        Instant.parse("2026-07-02T00:01:00Z"));

        store.saveVaultHeader(header);

        assertEquals(Optional.of(header), store.loadVaultHeader(header.vaultId()));
        Properties persisted = new Properties();
        try (var input = Files.newInputStream(tempDir.resolve("vault.properties"))) {
            persisted.load(input);
        }
        assertEquals("3", persisted.getProperty("kdfIterations"));
        assertEquals("3", persisted.getProperty("kdf.parameter.iterations"));
        assertEquals("64", persisted.getProperty("kdf.parameter.memoryKiB"));
        String serialized = Files.readString(tempDir.resolve("vault.properties"));
        assertTrue(
                serialized.indexOf("kdf.parameter.a=1") < serialized.indexOf("kdf.parameter.b=2"));
        assertTrue(
                serialized.indexOf("kdf.parameter.b=2")
                        < serialized.indexOf("kdf.parameter.iterations=3"));
        assertTrue(
                serialized.indexOf("kdf.parameter.iterations=3")
                        < serialized.indexOf("kdf.parameter.memoryKiB=64"));
    }

    @Test
    void legacyPbkdf2PropertyFixtureStillLoads() throws IOException {
        Files.writeString(
                tempDir.resolve("vault.properties"),
                """
                vaultId=00000000-0000-0000-0000-000000000001
                formatVersion=1
                kdfAlgorithm=PBKDF2WithHmacSHA256
                kdfSalt=AQID
                kdfIterations=120000
                vaultKeyId=vault-key
                wrappedVaultKey=BAUG
                createdAt=2026-07-02T00:00:00Z
                updatedAt=2026-07-02T00:01:00Z
                """);
        FileVaultStore store = new FileVaultStore(tempDir);

        VaultHeader loaded = store.loadVaultHeader(header().vaultId()).orElseThrow();

        assertEquals(header(), loaded);
        assertEquals(
                Map.of(KdfParameters.ITERATIONS, 120_000), loaded.kdfParameters().parameters());
    }

    @Test
    void vaultHeaderReaderRejectsEncodedSaltBeforeUnboundedBase64Decode() throws IOException {
        writeVaultHeaderFixture("!".repeat(89), Map.of());

        IllegalArgumentException failure =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> new FileVaultStore(tempDir).loadVaultHeader(header().vaultId()));

        assertTrue(failure.getMessage().contains("salt exceeds"));
    }

    @Test
    void vaultHeaderReaderRejectsDecodedSaltAbove64Bytes() throws IOException {
        writeVaultHeaderFixture(Base64.getEncoder().encodeToString(new byte[65]), Map.of());

        IllegalArgumentException failure =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> new FileVaultStore(tempDir).loadVaultHeader(header().vaultId()));

        assertTrue(failure.getMessage().contains("salt exceeds"));
    }

    @Test
    void vaultHeaderReaderRejectsSeventeenthCanonicalParameter() throws IOException {
        Map<String, String> parameters = new java.util.LinkedHashMap<>();
        for (int index = 0; index < 17; index++) {
            parameters.put("p" + index, "1");
        }
        writeVaultHeaderFixture("AQID", parameters);

        IllegalArgumentException failure =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> new FileVaultStore(tempDir).loadVaultHeader(header().vaultId()));

        assertTrue(failure.getMessage().contains("parameter count"));
    }

    @Test
    void saveVaultHeaderRejectsChangingVaultIdentity() {
        VaultStore store = new FileVaultStore(tempDir);
        VaultHeader first = header();
        VaultHeader second =
                new VaultHeader(
                        new VaultId(UUID.fromString("00000000-0000-0000-0000-000000000099")),
                        first.formatVersion(),
                        first.kdfAlgorithm(),
                        first.kdfSalt(),
                        first.kdfIterations(),
                        first.vaultKeyId(),
                        first.wrappedVaultKey(),
                        first.createdAt(),
                        first.updatedAt());

        store.saveVaultHeader(first);

        assertThrows(StoreException.class, () -> store.saveVaultHeader(second));
        assertEquals(Optional.of(first), store.loadVaultHeader(first.vaultId()));
        assertEquals(Optional.empty(), store.loadVaultHeader(second.vaultId()));
    }

    @Test
    void saveVaultHeaderRejectsUpdatedTimeRegression() {
        VaultStore store = new FileVaultStore(tempDir);
        VaultHeader first = header();
        VaultHeader stale =
                new VaultHeader(
                        first.vaultId(),
                        first.formatVersion(),
                        first.kdfAlgorithm(),
                        first.kdfSalt(),
                        first.kdfIterations(),
                        first.vaultKeyId(),
                        first.wrappedVaultKey(),
                        first.createdAt(),
                        first.updatedAt().minusSeconds(1));

        store.saveVaultHeader(first);

        assertThrows(StoreException.class, () -> store.saveVaultHeader(stale));
        assertEquals(Optional.of(first), store.loadVaultHeader(first.vaultId()));
    }

    @Test
    void saveVaultHeaderRejectsExistingSecretRecordFromDifferentVault() {
        VaultStore store = new FileVaultStore(tempDir);
        VaultHeader header = header();
        EncryptedSecretRecord record = record(vaultId(99L), secretId(99L), "Wrong vault", 1L);

        store.saveSecretRecord(record);

        assertThrows(StoreException.class, () -> store.saveVaultHeader(header));
        assertEquals(Optional.empty(), store.loadVaultHeader(header.vaultId()));
    }

    @Test
    void saveVaultHeaderRejectsExistingTombstoneFromDifferentVault() {
        VaultStore store = new FileVaultStore(tempDir);
        VaultHeader header = header();
        DeletedSecretRecord record = deleted(vaultId(99L), secretId(99L), 1L);

        store.saveDeletedSecretRecord(record);

        assertThrows(StoreException.class, () -> store.saveVaultHeader(header));
        assertEquals(Optional.empty(), store.loadVaultHeader(header.vaultId()));
    }

    @Test
    void saveVaultHeaderRejectsExistingSecretRecordWithoutVaultIdentity() throws IOException {
        VaultStore store = new FileVaultStore(tempDir);
        VaultHeader header = header();
        SecretId secretId = secretId(99L);
        Files.createDirectories(secretFile(secretId).getParent());
        Files.writeString(
                secretFile(secretId), "metadata.id=" + secretId.value() + "\nrecord.revision=1\n");

        assertThrows(StoreException.class, () -> store.saveVaultHeader(header));
        assertEquals(Optional.empty(), store.loadVaultHeader(header.vaultId()));
    }

    @Test
    void saveVaultHeaderRejectsExistingTombstoneWithoutVaultIdentity() throws IOException {
        VaultStore store = new FileVaultStore(tempDir);
        VaultHeader header = header();
        SecretId secretId = secretId(99L);
        Files.createDirectories(deletedFile(secretId).getParent());
        Files.writeString(deletedFile(secretId), "secretId=" + secretId.value() + "\nrevision=1\n");

        assertThrows(StoreException.class, () -> store.saveVaultHeader(header));
        assertEquals(Optional.empty(), store.loadVaultHeader(header.vaultId()));
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
    void saveSecretRecordRejectsDifferentVaultWhenHeaderExists() {
        VaultStore store = new FileVaultStore(tempDir);
        VaultHeader header = header();
        VaultId otherVaultId = vaultId(99L);
        SecretId secretId = secretId(99L);
        EncryptedSecretRecord record = record(otherVaultId, secretId, "Wrong vault", 1L);

        store.saveVaultHeader(header);

        assertThrows(StoreException.class, () -> store.saveSecretRecord(record));
        assertThrows(StoreException.class, () -> store.loadSecretRecord(otherVaultId, secretId));
        assertFalse(Files.exists(secretFile(secretId)));
    }

    @Test
    void saveDeletedSecretRecordRejectsDifferentVaultWhenHeaderExists() {
        VaultStore store = new FileVaultStore(tempDir);
        VaultHeader header = header();
        VaultId otherVaultId = vaultId(99L);
        SecretId secretId = secretId(99L);
        DeletedSecretRecord record = deleted(otherVaultId, secretId, 1L);

        store.saveVaultHeader(header);

        assertThrows(StoreException.class, () -> store.saveDeletedSecretRecord(record));
        assertThrows(
                StoreException.class, () -> store.loadDeletedSecretRecord(otherVaultId, secretId));
        assertFalse(Files.exists(deletedFile(secretId)));
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
        assertEquals("github.com", metadata.classification().software());
        assertEquals("alice@example.com", metadata.classification().account());
        assertEquals(Set.of("work"), metadata.classification().labels());
        assertEquals(Map.of("project", "keystead"), metadata.profile().attributes());
    }

    @Test
    void loadSecretRecordRejectsDifferentVaultWhenHeaderExists() throws IOException {
        VaultStore store = new FileVaultStore(tempDir);
        VaultId otherVaultId = vaultId(99L);
        SecretId secretId = secretId(99L);
        String recordFile = savedSecretRecordFileFor(otherVaultId, secretId);
        store.saveVaultHeader(header());
        Files.createDirectories(secretFile(secretId).getParent());
        Files.writeString(secretFile(secretId), recordFile);

        assertThrows(StoreException.class, () -> store.loadSecretRecord(otherVaultId, secretId));
        assertEquals(Optional.empty(), store.loadSecretRecord(header().vaultId(), secretId));
    }

    @Test
    void loadDeletedSecretRecordRejectsDifferentVaultWhenHeaderExists() throws IOException {
        VaultStore store = new FileVaultStore(tempDir);
        VaultId otherVaultId = vaultId(99L);
        SecretId secretId = secretId(99L);
        String tombstoneFile = savedDeletedRecordFileFor(otherVaultId, secretId);
        store.saveVaultHeader(header());
        Files.createDirectories(deletedFile(secretId).getParent());
        Files.writeString(deletedFile(secretId), tombstoneFile);

        assertThrows(
                StoreException.class, () -> store.loadDeletedSecretRecord(otherVaultId, secretId));
        assertEquals(Optional.empty(), store.loadDeletedSecretRecord(header().vaultId(), secretId));
    }

    @Test
    void loadSecretRecordRejectsFileWhoseMetadataIdDoesNotMatchPath() throws IOException {
        VaultStore store = new FileVaultStore(tempDir);
        SecretId requestedSecretId = secretId(99L);
        EncryptedSecretRecord storedRecord = record(secretId(2L), "GitHub", 1L);
        store.saveSecretRecord(storedRecord);
        String recordFile = Files.readString(secretFile(storedRecord.metadata().id()));
        Files.writeString(secretFile(requestedSecretId), recordFile);

        assertThrows(
                StoreException.class,
                () -> store.loadSecretRecord(storedRecord.vaultId(), requestedSecretId));
    }

    @Test
    void loadDeletedSecretRecordRejectsFileWhoseSecretIdDoesNotMatchPath() throws IOException {
        VaultStore store = new FileVaultStore(tempDir);
        SecretId requestedSecretId = secretId(99L);
        DeletedSecretRecord storedRecord = deleted(secretId(2L), 1L);
        store.saveDeletedSecretRecord(storedRecord);
        String tombstoneFile = Files.readString(deletedFile(storedRecord.secretId()));
        Files.writeString(deletedFile(requestedSecretId), tombstoneFile);

        assertThrows(
                StoreException.class,
                () -> store.loadDeletedSecretRecord(storedRecord.vaultId(), requestedSecretId));
    }

    @Test
    void listsMetadataWithoutOpeningPayload() {
        VaultStore store = new FileVaultStore(tempDir);
        EncryptedSecretRecord record = record();

        store.saveSecretRecord(record);

        assertEquals(List.of(record.metadata()), store.listMetadata(record.vaultId()));
    }

    @Test
    void listMetadataSkipsCorruptSecretFiles() throws IOException {
        VaultStore store = new FileVaultStore(tempDir);
        EncryptedSecretRecord valid = record();
        store.saveSecretRecord(valid);

        // A truncated/corrupt secret file (e.g. left by a crashed non-atomic write) that
        // matches the vault id but is missing every required field must not brick listing.
        Path corrupt =
                tempDir.resolve("secrets")
                        .resolve("00000000-0000-0000-0000-000000000099.properties");
        Files.writeString(corrupt, "vaultId=" + valid.vaultId().value() + "\n");

        assertEquals(List.of(valid.metadata()), store.listMetadata(valid.vaultId()));
        assertEquals(List.of(valid), store.listSecretRecords(valid.vaultId()));
    }

    @Test
    void listSecretRecordsSkipsFileWhoseMetadataIdDoesNotMatchPath() throws IOException {
        VaultStore store = new FileVaultStore(tempDir);
        SecretId wrongPathSecretId = secretId(99L);
        EncryptedSecretRecord valid = record(secretId(2L), "GitHub", 1L);
        store.saveSecretRecord(valid);
        String recordFile = Files.readString(secretFile(valid.metadata().id()));
        Files.writeString(secretFile(wrongPathSecretId), recordFile);

        assertEquals(List.of(valid), store.listSecretRecords(valid.vaultId()));
    }

    @Test
    void listSecretRecordsRejectsDifferentVaultWhenHeaderExists() throws IOException {
        VaultStore store = new FileVaultStore(tempDir);
        VaultId otherVaultId = vaultId(99L);
        SecretId secretId = secretId(99L);
        String recordFile = savedSecretRecordFileFor(otherVaultId, secretId);
        store.saveVaultHeader(header());
        Files.createDirectories(secretFile(secretId).getParent());
        Files.writeString(secretFile(secretId), recordFile);

        assertThrows(StoreException.class, () -> store.listSecretRecords(otherVaultId));
        assertThrows(StoreException.class, () -> store.listMetadata(otherVaultId));
        assertEquals(List.of(), store.listSecretRecords(header().vaultId()));
    }

    @Test
    void listDeletedSecretRecordsRejectsDifferentVaultWhenHeaderExists() throws IOException {
        VaultStore store = new FileVaultStore(tempDir);
        VaultId otherVaultId = vaultId(99L);
        SecretId secretId = secretId(99L);
        String tombstoneFile = savedDeletedRecordFileFor(otherVaultId, secretId);
        store.saveVaultHeader(header());
        Files.createDirectories(deletedFile(secretId).getParent());
        Files.writeString(deletedFile(secretId), tombstoneFile);

        assertThrows(StoreException.class, () -> store.listDeletedSecretRecords(otherVaultId));
        assertEquals(List.of(), store.listDeletedSecretRecords(header().vaultId()));
    }

    @Test
    void listDeletedSecretRecordsSkipsFileWhoseSecretIdDoesNotMatchPath() throws IOException {
        VaultStore store = new FileVaultStore(tempDir);
        SecretId wrongPathSecretId = secretId(99L);
        DeletedSecretRecord valid = deleted(secretId(2L), 1L);
        store.saveDeletedSecretRecord(valid);
        String tombstoneFile = Files.readString(deletedFile(valid.secretId()));
        Files.writeString(deletedFile(wrongPathSecretId), tombstoneFile);

        assertEquals(List.of(valid), store.listDeletedSecretRecords(valid.vaultId()));
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
    void deleteSecretRecordRejectsDifferentVaultWhenHeaderExists() {
        VaultStore store = new FileVaultStore(tempDir);
        EncryptedSecretRecord record = record();
        VaultId otherVaultId = vaultId(99L);

        store.saveVaultHeader(header());
        store.saveSecretRecord(record);

        assertThrows(
                StoreException.class,
                () -> store.deleteSecretRecord(otherVaultId, record.metadata().id()));
        assertEquals(
                Optional.of(record),
                store.loadSecretRecord(record.vaultId(), record.metadata().id()));
    }

    @Test
    void deleteDeletedSecretRecordRejectsDifferentVaultWhenHeaderExists() {
        VaultStore store = new FileVaultStore(tempDir);
        DeletedSecretRecord record = deleted(secretId(2L), 1L);
        VaultId otherVaultId = vaultId(99L);

        store.saveVaultHeader(header());
        store.saveDeletedSecretRecord(record);

        assertThrows(
                StoreException.class,
                () -> store.deleteDeletedSecretRecord(otherVaultId, record.secretId()));
        assertEquals(
                Optional.of(record),
                store.loadDeletedSecretRecord(record.vaultId(), record.secretId()));
    }

    @Test
    void newerTombstoneHidesStaleSecretRecordAfterInterruptedDelete() {
        VaultStore store = new FileVaultStore(tempDir);
        EncryptedSecretRecord record = record(secretId(2L), "GitHub", 1L);
        DeletedSecretRecord tombstone = deleted(record, 2L);

        store.saveSecretRecord(record);
        store.saveDeletedSecretRecord(tombstone);

        assertEquals(
                Optional.empty(), store.loadSecretRecord(record.vaultId(), record.metadata().id()));
        assertEquals(List.of(), store.listSecretRecords(record.vaultId()));
        assertEquals(List.of(), store.listMetadata(record.vaultId()));
        assertEquals(List.of(tombstone), store.listDeletedSecretRecords(record.vaultId()));
    }

    @Test
    void newerSecretRecordHidesStaleTombstoneAfterInterruptedRestore() {
        VaultStore store = new FileVaultStore(tempDir);
        EncryptedSecretRecord record = record(secretId(2L), "GitHub", 2L);
        DeletedSecretRecord staleTombstone = deleted(record, 1L);

        store.saveSecretRecord(record);
        store.saveDeletedSecretRecord(staleTombstone);

        assertEquals(
                Optional.empty(),
                store.loadDeletedSecretRecord(record.vaultId(), record.metadata().id()));
        assertEquals(List.of(), store.listDeletedSecretRecords(record.vaultId()));
        assertEquals(List.of(record), store.listSecretRecords(record.vaultId()));
        assertEquals(List.of(record.metadata()), store.listMetadata(record.vaultId()));
    }

    @Test
    void saveSecretRecordSkipsRecordOlderThanExistingTombstone() {
        VaultStore store = new FileVaultStore(tempDir);
        SecretId secretId = secretId(2L);
        DeletedSecretRecord tombstone = deleted(secretId, 2L);
        EncryptedSecretRecord staleRecord = record(secretId, "GitHub", 1L);

        store.saveDeletedSecretRecord(tombstone);
        store.saveSecretRecord(staleRecord);

        assertEquals(List.of(), store.listSecretRecords(staleRecord.vaultId()));
        assertEquals(List.of(tombstone), store.listDeletedSecretRecords(staleRecord.vaultId()));
        assertFalse(Files.exists(secretFile(secretId)));
        assertTrue(Files.exists(deletedFile(secretId)));
    }

    @Test
    void saveDeletedSecretRecordDeletesOlderSecretRecord() {
        VaultStore store = new FileVaultStore(tempDir);
        SecretId secretId = secretId(2L);
        EncryptedSecretRecord record = record(secretId, "GitHub", 1L);
        DeletedSecretRecord tombstone = deleted(secretId, 2L);

        store.saveSecretRecord(record);
        store.saveDeletedSecretRecord(tombstone);

        assertEquals(List.of(), store.listSecretRecords(record.vaultId()));
        assertEquals(List.of(tombstone), store.listDeletedSecretRecords(record.vaultId()));
        assertFalse(Files.exists(secretFile(secretId)));
        assertTrue(Files.exists(deletedFile(secretId)));
    }

    @Test
    void saveDeletedSecretRecordSkipsTombstoneOlderThanExistingRecord() {
        VaultStore store = new FileVaultStore(tempDir);
        SecretId secretId = secretId(2L);
        EncryptedSecretRecord record = record(secretId, "GitHub", 2L);
        DeletedSecretRecord staleTombstone = deleted(secretId, 1L);

        store.saveSecretRecord(record);
        store.saveDeletedSecretRecord(staleTombstone);

        assertEquals(List.of(record), store.listSecretRecords(record.vaultId()));
        assertEquals(List.of(), store.listDeletedSecretRecords(record.vaultId()));
        assertTrue(Files.exists(secretFile(secretId)));
        assertFalse(Files.exists(deletedFile(secretId)));
    }

    @Test
    void commitMutationRecoversStaleSecretRecordFile() throws IOException {
        VaultStore store = new FileVaultStore(tempDir);
        VaultId vaultId = header().vaultId();
        SecretId secretId = secretId(2L);
        EncryptedSecretRecord record = record(secretId, "GitHub", 1L);
        DeletedSecretRecord tombstone = deleted(secretId, 2L);

        store.saveSecretRecord(record);
        String staleRecordFile = Files.readString(secretFile(secretId));
        store.saveDeletedSecretRecord(tombstone);
        Files.createDirectories(secretFile(secretId).getParent());
        Files.writeString(secretFile(secretId), staleRecordFile);

        store.commitMutation(vaultId, revision -> assertEquals(3L, revision));

        assertFalse(Files.exists(secretFile(secretId)));
        assertEquals(List.of(tombstone), store.listDeletedSecretRecords(vaultId));
    }

    @Test
    void commitMutationRejectsDifferentVaultBeforeRecovery() throws IOException {
        VaultStore store = new FileVaultStore(tempDir);
        VaultId rootVaultId = header().vaultId();
        VaultId otherVaultId = vaultId(99L);
        SecretId secretId = secretId(99L);
        EncryptedSecretRecord staleRecord = record(otherVaultId, secretId, "Wrong vault", 1L);
        DeletedSecretRecord tombstone = deleted(otherVaultId, secretId, 2L);

        store.saveSecretRecord(staleRecord);
        String staleRecordFile = Files.readString(secretFile(secretId));
        store.saveDeletedSecretRecord(tombstone);
        String tombstoneFile = Files.readString(deletedFile(secretId));
        Files.deleteIfExists(secretFile(secretId));
        Files.deleteIfExists(deletedFile(secretId));
        store.saveVaultHeader(header());
        Files.createDirectories(secretFile(secretId).getParent());
        Files.createDirectories(deletedFile(secretId).getParent());
        Files.writeString(secretFile(secretId), staleRecordFile);
        Files.writeString(deletedFile(secretId), tombstoneFile);

        assertThrows(
                StoreException.class,
                () ->
                        store.commitMutation(
                                otherVaultId, revision -> fail("mutation should not run")));
        assertTrue(Files.exists(secretFile(secretId)));
        assertThrows(StoreException.class, () -> store.listDeletedSecretRecords(otherVaultId));
        assertEquals(List.of(), store.listSecretRecords(rootVaultId));
    }

    @Test
    void commitMutationRecoversStaleTombstoneFile() throws IOException {
        VaultStore store = new FileVaultStore(tempDir);
        VaultId vaultId = header().vaultId();
        SecretId secretId = secretId(2L);
        DeletedSecretRecord tombstone = deleted(secretId, 1L);
        EncryptedSecretRecord record = record(secretId, "GitHub", 2L);

        store.saveDeletedSecretRecord(tombstone);
        String staleTombstoneFile = Files.readString(deletedFile(secretId));
        store.saveSecretRecord(record);
        Files.createDirectories(deletedFile(secretId).getParent());
        Files.writeString(deletedFile(secretId), staleTombstoneFile);

        store.commitMutation(vaultId, revision -> assertEquals(3L, revision));

        assertFalse(Files.exists(deletedFile(secretId)));
        assertEquals(List.of(record), store.listSecretRecords(vaultId));
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

    @Test
    void secretRecordFileDoesNotStoreEnvelopeAad() throws IOException {
        VaultStore store = new FileVaultStore(tempDir);
        EncryptedSecretRecord record = record();

        store.saveSecretRecord(record);

        String file = Files.readString(secretFile(record.metadata().id()));
        assertFalse(file.contains("envelope.aad"));
    }

    @Test
    void loadSecretRecordPreservesLegacySerializedEnvelopeAad() throws IOException {
        VaultStore store = new FileVaultStore(tempDir);
        EncryptedSecretRecord record = record();
        byte[] legacyAad = new byte[] {4, 5, 6};

        store.saveSecretRecord(record);
        Path path = secretFile(record.metadata().id());
        Files.writeString(path, Files.readString(path) + "\nenvelope.aad=BAUG\n");

        EncryptedSecretRecord loaded =
                store.loadSecretRecord(record.vaultId(), record.metadata().id()).orElseThrow();
        assertArrayEquals(legacyAad, loaded.payload().aad());
    }

    @Test
    void legacyAadOneByteOverLimitIsRejectedBeforeBase64DecoderAllocation() throws IOException {
        FileVaultStore setup = new FileVaultStore(tempDir);
        EncryptedSecretRecord record = record();
        setup.saveSecretRecord(record);
        Path path = secretFile(record.metadata().id());
        String encoded =
                Base64.getEncoder()
                        .encodeToString(new byte[SecurityLimits.MAX_ENVELOPE_AAD_BYTES + 1]);
        Files.writeString(path, Files.readString(path) + "\nenvelope.aad=" + encoded + "\n");

        FileVaultStore store =
                new FileVaultStore(
                        tempDir,
                        (durablePath, metadata) -> {},
                        (field, value) -> {
                            if (field.equals("envelope.aad")) {
                                throw new AssertionError("decoder must not run");
                            }
                            return Base64.getDecoder().decode(value);
                        });

        IllegalArgumentException failure =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> store.loadSecretRecord(record.vaultId(), record.metadata().id()));
        assertEquals("Vault envelope AAD exceeds the size limit", failure.getMessage());
    }

    @Test
    void serializedRecordOverLimitDoesNotReplacePreviousRowOrAdvanceRevision() {
        FileVaultStore store = new FileVaultStore(tempDir);
        EncryptedSecretRecord previous = record();
        store.saveSecretRecord(previous);
        EncryptedSecretRecord candidate =
                record(previous.metadata().id(), "replacement", previous.revision() + 1);
        EncryptedEnvelope oversizedEnvelope =
                new EncryptedEnvelope(
                        candidate.payload().version(),
                        candidate.payload().algorithm(),
                        candidate.payload().keyId(),
                        candidate.payload().nonce(),
                        candidate.payload().aad(),
                        new byte[SecurityLimits.MAX_ENVELOPE_CIPHERTEXT_BYTES],
                        candidate.payload().encryptedAt());
        EncryptedSecretRecord replacement =
                new EncryptedSecretRecord(
                        candidate.vaultId(),
                        candidate.metadata(),
                        oversizedEnvelope,
                        candidate.revision());

        StoreException failure =
                assertThrows(StoreException.class, () -> store.saveSecretRecord(replacement));

        assertEquals("Vault properties exceed the size limit", failure.getMessage());
        assertEquals(
                Optional.of(previous),
                store.loadSecretRecord(previous.vaultId(), previous.metadata().id()));
        assertEquals(previous.revision() + 1, store.nextRevision(previous.vaultId()));
    }

    @Test
    void nextRevisionDoesNotAdvanceDurableRevisionUntilRecordCommits() {
        VaultStore store = new FileVaultStore(tempDir);
        EncryptedSecretRecord record = record();

        assertEquals(1L, store.nextRevision(record.vaultId()));
        assertEquals(1L, store.nextRevision(record.vaultId()));

        store.saveSecretRecord(record);

        assertEquals(2L, store.nextRevision(record.vaultId()));
    }

    @Test
    void nextRevisionRejectsDifferentVaultWhenHeaderExists() {
        VaultStore store = new FileVaultStore(tempDir);
        VaultHeader header = header();
        VaultId otherVaultId = vaultId(99L);

        store.saveVaultHeader(header);

        assertThrows(StoreException.class, () -> store.nextRevision(otherVaultId));
    }

    @Test
    void recordRevisionRejectsDifferentVaultWhenHeaderExists() throws IOException {
        VaultStore store = new FileVaultStore(tempDir);
        VaultHeader header = header();
        VaultId otherVaultId = vaultId(99L);

        store.saveVaultHeader(header);

        assertThrows(StoreException.class, () -> store.recordRevision(otherVaultId, 1L));
        assertFalse(Files.exists(tempDir.resolve("revisions.properties")));
    }

    @Test
    void nextRevisionRecoversFromStaleDurableRevisionIndex() throws IOException {
        VaultStore store = new FileVaultStore(tempDir);
        VaultId vaultId = header().vaultId();
        store.saveSecretRecord(record(secretId(20L), "first", 1L));
        store.saveSecretRecord(record(secretId(21L), "second", 2L));
        Files.writeString(
                tempDir.resolve("revisions.properties"),
                "vault." + vaultId.value() + ".lastRevision=1\n");

        assertEquals(3L, store.nextRevision(vaultId));
    }

    @Test
    void committedMutationsSerializeRevisionAllocationAndWrites() throws Exception {
        VaultStore store = new FileVaultStore(tempDir);
        VaultId vaultId = header().vaultId();
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<?> first =
                    executor.submit(
                            () -> {
                                await(start);
                                store.commitMutation(
                                        vaultId,
                                        revision ->
                                                store.saveSecretRecord(
                                                        record(secretId(20L), "first", revision)));
                            });
            Future<?> second =
                    executor.submit(
                            () -> {
                                await(start);
                                store.commitMutation(
                                        vaultId,
                                        revision ->
                                                store.saveSecretRecord(
                                                        record(secretId(21L), "second", revision)));
                            });

            start.countDown();

            first.get(5, TimeUnit.SECONDS);
            second.get(5, TimeUnit.SECONDS);
        } finally {
            executor.shutdownNow();
        }

        assertEquals(
                List.of(1L, 2L),
                store.listSecretRecords(vaultId).stream()
                        .map(EncryptedSecretRecord::revision)
                        .sorted()
                        .toList());
    }

    @Test
    void committedMutationsSerializeAcrossStoreInstances() throws Exception {
        VaultStore firstStore = new FileVaultStore(tempDir);
        VaultStore secondStore = new FileVaultStore(tempDir);
        VaultId vaultId = header().vaultId();
        CountDownLatch firstAllocated = new CountDownLatch(1);
        CountDownLatch releaseFirst = new CountDownLatch(1);
        CountDownLatch secondAllocated = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<?> first =
                    executor.submit(
                            () ->
                                    firstStore.commitMutation(
                                            vaultId,
                                            revision -> {
                                                firstAllocated.countDown();
                                                await(releaseFirst);
                                                firstStore.saveSecretRecord(
                                                        record(secretId(30L), "first", revision));
                                            }));
            assertTrue(
                    firstAllocated.await(5, TimeUnit.SECONDS),
                    "first mutation did not allocate a revision");

            Future<?> second =
                    executor.submit(
                            () ->
                                    secondStore.commitMutation(
                                            vaultId,
                                            revision -> {
                                                secondAllocated.countDown();
                                                secondStore.saveSecretRecord(
                                                        record(secretId(31L), "second", revision));
                                            }));

            secondAllocated.await(250, TimeUnit.MILLISECONDS);
            releaseFirst.countDown();

            first.get(5, TimeUnit.SECONDS);
            second.get(5, TimeUnit.SECONDS);
        } finally {
            releaseFirst.countDown();
            executor.shutdownNow();
        }

        assertEquals(
                List.of(1L, 2L),
                firstStore.listSecretRecords(vaultId).stream()
                        .map(EncryptedSecretRecord::revision)
                        .sorted()
                        .toList());
    }

    @Test
    void atomicStoreLeavesPreviousContentIntactWhenWriteFails() throws IOException {
        VaultStore store = new FileVaultStore(tempDir);
        VaultHeader first = header();
        store.saveVaultHeader(first);
        assertEquals(Optional.of(first), store.loadVaultHeader(first.vaultId()));

        // Restrict the vault DIRECTORY so new files cannot be created in it, while the
        // existing vault.properties remains writable in place. A non-atomic in-place
        // overwrite would silently corrupt the file; an atomic temp+move must fail and
        // leave the previous content intact.
        boolean restricted = restrictDirectoryNewFileCreation(tempDir);
        Assumptions.assumeTrue(
                restricted, "filesystem does not support restricting directory writes");
        try {
            VaultHeader second =
                    new VaultHeader(
                            first.vaultId(),
                            first.formatVersion(),
                            first.kdfAlgorithm(),
                            first.kdfSalt(),
                            first.kdfIterations(),
                            first.vaultKeyId(),
                            new byte[] {99, 98, 97},
                            first.createdAt(),
                            Instant.parse("2026-07-02T00:09:00Z"));

            assertThrows(StoreException.class, () -> store.saveVaultHeader(second));
            assertEquals(Optional.of(first), store.loadVaultHeader(first.vaultId()));
        } finally {
            releaseDirectoryNewFileCreation(tempDir);
        }
    }

    @Test
    void storeForcesTempFileAndParentDirectoryWhenCommittingProperties() {
        List<String> forcedPaths = new ArrayList<>();
        VaultStore store =
                new FileVaultStore(
                        tempDir,
                        (path, metadata) ->
                                forcedPaths.add(
                                        tempDir.relativize(path).toString() + ":" + metadata));

        store.saveVaultHeader(header());

        assertEquals(2, forcedPaths.size());
        assertTrue(forcedPaths.get(0).startsWith("vault.properties."));
        assertTrue(
                forcedPaths.get(0).endsWith(".tmp:true"),
                "properties writes must flush the temp file before the atomic move");
        assertEquals(
                ":true", forcedPaths.get(1), "properties writes must flush the parent directory");
    }

    @Test
    void eachPropertiesCommitUsesUniqueSiblingTempFile() {
        List<String> tempFiles = new ArrayList<>();
        VaultStore store =
                new FileVaultStore(
                        tempDir,
                        (path, metadata) -> {
                            String fileName = path.getFileName().toString();
                            if (fileName.startsWith("vault.properties")
                                    && fileName.endsWith(".tmp")) {
                                tempFiles.add(fileName);
                            }
                        });

        store.saveVaultHeader(header());
        store.saveVaultHeader(header());

        assertEquals(2, tempFiles.size());
        assertEquals(
                2,
                Set.copyOf(tempFiles).size(),
                "independent commits must not share a deterministic temp file name");
    }

    @Test
    void deleteSecretRecordForcesParentDirectoryAfterRemovingRecord() {
        List<String> forcedPaths = new ArrayList<>();
        VaultStore store =
                new FileVaultStore(
                        tempDir,
                        (path, metadata) ->
                                forcedPaths.add(
                                        tempDir.relativize(path).toString() + ":" + metadata));
        EncryptedSecretRecord record = record();
        store.saveSecretRecord(record);
        forcedPaths.clear();

        store.deleteSecretRecord(record.vaultId(), record.metadata().id());

        assertEquals(List.of("secrets:true"), forcedPaths);
    }

    @Test
    void rotationRecoveryRestoresPreviousVaultWhenCrashFollowsPreparedJournal() {
        VaultHeader previous = header();
        EncryptedSecretRecord previousRecord = record();
        FileVaultStore setup = new FileVaultStore(tempDir);
        setup.saveVaultHeader(previous);
        setup.saveSecretRecord(previousRecord);

        assertThrows(
                StoreException.class,
                () -> crashDuringRotation(6).commitVaultKeyRotation(rotation(previousRecord)));

        assertRecoveredRotation(previous, previousRecord);
    }

    @Test
    void rotationRecoveryRestoresPreviousVaultWhenCrashPreventsCommittedJournal() {
        VaultHeader previous = header();
        EncryptedSecretRecord previousRecord = record();
        FileVaultStore setup = new FileVaultStore(tempDir);
        setup.saveVaultHeader(previous);
        setup.saveSecretRecord(previousRecord);

        assertThrows(
                StoreException.class,
                () -> crashDuringRotation(7).commitVaultKeyRotation(rotation(previousRecord)));

        assertRecoveredRotation(previous, previousRecord);
    }

    @Test
    void rotationRecoveryKeepsReplacementVaultWhenCrashFollowsCommittedJournal() {
        VaultHeader previous = header();
        EncryptedSecretRecord previousRecord = record();
        FileVaultStore setup = new FileVaultStore(tempDir);
        setup.saveVaultHeader(previous);
        setup.saveSecretRecord(previousRecord);
        VaultKeyRotation rotation = rotation(previousRecord);

        assertThrows(
                StoreException.class,
                () -> crashDuringRotation(8).commitVaultKeyRotation(rotation));

        FileVaultStore recovered = new FileVaultStore(tempDir);
        assertEquals(Optional.of(rotation.header()), recovered.loadVaultHeader(previous.vaultId()));
        assertEquals(
                Optional.of(rotation.activeRecords().getFirst()),
                recovered.loadSecretRecord(previous.vaultId(), previousRecord.metadata().id()));
    }

    private @NonNull FileVaultStore crashDuringRotation(int durabilityForce) {
        AtomicInteger durabilityForces = new AtomicInteger();
        return new FileVaultStore(
                tempDir,
                (path, metadata) -> {
                    if (durabilityForces.incrementAndGet() == durabilityForce) {
                        throw new IOException(
                                "simulated crash after rotation journal durability boundary");
                    }
                });
    }

    @Test
    void rotationCrashDuringStagingLeavesPreviousVaultUntouchedAndRetryable() {
        VaultHeader previous = header();
        EncryptedSecretRecord previousRecord = record();
        FileVaultStore setup = new FileVaultStore(tempDir);
        setup.saveVaultHeader(previous);
        setup.saveSecretRecord(previousRecord);

        assertThrows(
                StoreException.class,
                () -> crashDuringRotation(4).commitVaultKeyRotation(rotation(previousRecord)));

        // The staged replacement was written but no journal exists, so recovery is a no-op and
        // the previous vault is intact; a retry must first clean the stale stage directory.
        assertRecoveredRotation(previous, previousRecord);

        FileVaultStore retry = new FileVaultStore(tempDir);
        VaultKeyRotation rotation = rotation(previousRecord);
        retry.commitVaultKeyRotation(rotation);
        assertEquals(Optional.of(rotation.header()), retry.loadVaultHeader(previous.vaultId()));
        assertEquals(
                Optional.of(rotation.activeRecords().getFirst()),
                retry.loadSecretRecord(previous.vaultId(), previousRecord.metadata().id()));
    }

    @Test
    void rotationCrashBeforeJournalBecomesDurableLeavesNoJournalToRecover() {
        VaultHeader previous = header();
        EncryptedSecretRecord previousRecord = record();
        FileVaultStore setup = new FileVaultStore(tempDir);
        setup.saveVaultHeader(previous);
        setup.saveSecretRecord(previousRecord);

        assertThrows(
                StoreException.class,
                () -> crashDuringRotation(5).commitVaultKeyRotation(rotation(previousRecord)));

        // The PREPARED journal temp file was forced but never moved into place, so no journal
        // exists, recovery is a no-op, and the previous vault is intact.
        assertFalse(Files.exists(tempDir.resolve(".keystead-rotation.properties")));
        assertRecoveredRotation(previous, previousRecord);
    }

    @Test
    void rotationRetrySucceedsAfterRecoveryFromCrashFollowingPreparedJournal() {
        VaultHeader previous = header();
        EncryptedSecretRecord previousRecord = record();
        FileVaultStore setup = new FileVaultStore(tempDir);
        setup.saveVaultHeader(previous);
        setup.saveSecretRecord(previousRecord);

        assertThrows(
                StoreException.class,
                () -> crashDuringRotation(6).commitVaultKeyRotation(rotation(previousRecord)));

        assertRecoveredRotation(previous, previousRecord);

        FileVaultStore retry = new FileVaultStore(tempDir);
        VaultKeyRotation rotation = rotation(previousRecord);
        retry.commitVaultKeyRotation(rotation);
        assertEquals(Optional.of(rotation.header()), retry.loadVaultHeader(previous.vaultId()));
        assertEquals(
                Optional.of(rotation.activeRecords().getFirst()),
                retry.loadSecretRecord(previous.vaultId(), previousRecord.metadata().id()));
    }

    @Test
    void rotationCrashAfterJournalDeletionLeavesCommittedVaultConsistent() {
        VaultHeader previous = header();
        EncryptedSecretRecord previousRecord = record();
        FileVaultStore setup = new FileVaultStore(tempDir);
        setup.saveVaultHeader(previous);
        setup.saveSecretRecord(previousRecord);
        VaultKeyRotation rotation = rotation(previousRecord);

        assertThrows(
                StoreException.class,
                () -> crashDuringRotation(9).commitVaultKeyRotation(rotation));

        // The journal delete had already happened when the simulated crash hit its directory
        // force, so the rotation had effectively committed: recovery is a no-op and the
        // replacement vault is consistent despite the reported failure.
        FileVaultStore recovered = new FileVaultStore(tempDir);
        assertEquals(Optional.of(rotation.header()), recovered.loadVaultHeader(previous.vaultId()));
        assertEquals(
                Optional.of(rotation.activeRecords().getFirst()),
                recovered.loadSecretRecord(previous.vaultId(), previousRecord.metadata().id()));
        assertFalse(Files.exists(tempDir.resolve(".keystead-rotation.properties")));
        assertFalse(Files.exists(tempDir.resolve(".keystead-rotation-backup")));
        assertFalse(Files.exists(tempDir.resolve(".keystead-rotation-stage")));
    }

    private void assertRecoveredRotation(
            @NonNull VaultHeader previous, @NonNull EncryptedSecretRecord previousRecord) {
        FileVaultStore recovered = new FileVaultStore(tempDir);
        assertEquals(Optional.of(previous), recovered.loadVaultHeader(previous.vaultId()));
        assertEquals(
                Optional.of(previousRecord),
                recovered.loadSecretRecord(previous.vaultId(), previousRecord.metadata().id()));
    }

    private static @NonNull VaultKeyRotation rotation(
            @NonNull EncryptedSecretRecord previousRecord) {
        VaultHeader previous = header();
        VaultHeader replacement =
                new VaultHeader(
                        previous.vaultId(),
                        previous.formatVersion(),
                        previous.kdfAlgorithm(),
                        previous.kdfSalt(),
                        previous.kdfIterations(),
                        new KeyId("rotated-vault-key"),
                        new byte[] {9, 8, 7},
                        previous.createdAt(),
                        previous.updatedAt().plusSeconds(1));
        EncryptedEnvelope previousEnvelope = previousRecord.payload();
        EncryptedEnvelope envelope =
                new EncryptedEnvelope(
                        previousEnvelope.version(),
                        previousEnvelope.algorithm(),
                        replacement.vaultKeyId(),
                        previousEnvelope.nonce(),
                        previousEnvelope.aad(),
                        previousEnvelope.ciphertext(),
                        previousEnvelope.encryptedAt());
        return new VaultKeyRotation(
                replacement,
                List.of(
                        new EncryptedSecretRecord(
                                previousRecord.vaultId(),
                                previousRecord.metadata(),
                                envelope,
                                previousRecord.revision())));
    }

    private static boolean restrictDirectoryNewFileCreation(Path directory) {
        try {
            if (Files.getFileStore(directory).supportsFileAttributeView("acl")) {
                AclFileAttributeView view =
                        Files.getFileAttributeView(directory, AclFileAttributeView.class);
                UserPrincipal owner = Files.getOwner(directory);
                AclEntry deny =
                        AclEntry.newBuilder()
                                .setType(AclEntryType.DENY)
                                .setPrincipal(owner)
                                .setPermissions(AclEntryPermission.ADD_FILE)
                                .build();
                List<AclEntry> acl = new ArrayList<>(view.getAcl());
                acl.add(0, deny);
                view.setAcl(acl);
                return true;
            }
            if (Files.getFileStore(directory).supportsFileAttributeView("posix")) {
                Files.setPosixFilePermissions(
                        directory, PosixFilePermissions.fromString("r-xr-xr-x"));
                return true;
            }
        } catch (UnsupportedOperationException | IOException ignored) {
            // Fall through to "unsupported".
        }
        return false;
    }

    private static void releaseDirectoryNewFileCreation(Path directory) {
        try {
            if (Files.getFileStore(directory).supportsFileAttributeView("acl")) {
                AclFileAttributeView view =
                        Files.getFileAttributeView(directory, AclFileAttributeView.class);
                UserPrincipal owner = Files.getOwner(directory);
                List<AclEntry> acl = new ArrayList<>(view.getAcl());
                acl.removeIf(
                        entry ->
                                entry.type() == AclEntryType.DENY
                                        && owner.equals(entry.principal())
                                        && entry.permissions()
                                                .equals(Set.of(AclEntryPermission.ADD_FILE)));
                view.setAcl(acl);
            } else if (Files.getFileStore(directory).supportsFileAttributeView("posix")) {
                Files.setPosixFilePermissions(
                        directory, PosixFilePermissions.fromString("rwxrwxrwx"));
            }
        } catch (IOException ignored) {
            // Best effort; @TempDir cleanup may be noisier but the test already asserted.
        }
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

    private void writeVaultHeaderFixture(
            @NonNull String encodedSalt, @NonNull Map<String, String> parameters)
            throws IOException {
        StringBuilder fixture =
                new StringBuilder(
                        """
                        vaultId=00000000-0000-0000-0000-000000000001
                        formatVersion=1
                        kdfAlgorithm=PBKDF2WithHmacSHA256
                        kdfIterations=120000
                        vaultKeyId=vault-key
                        wrappedVaultKey=BAUG
                        createdAt=2026-07-02T00:00:00Z
                        updatedAt=2026-07-02T00:01:00Z
                        """);
        fixture.append("kdfSalt=").append(encodedSalt).append('\n');
        parameters.forEach(
                (name, value) ->
                        fixture.append("kdf.parameter.")
                                .append(name)
                                .append('=')
                                .append(value)
                                .append('\n'));
        Files.writeString(tempDir.resolve("vault.properties"), fixture);
    }

    private static EncryptedSecretRecord record() {
        return record(secretId(2L), "GitHub", 1L);
    }

    private static EncryptedSecretRecord record(
            @NonNull SecretId secretId, @NonNull String title, long revision) {
        return record(header().vaultId(), secretId, title, revision);
    }

    private static EncryptedSecretRecord record(
            @NonNull VaultId vaultId,
            @NonNull SecretId secretId,
            @NonNull String title,
            long revision) {
        SecretMetadata metadata =
                new SecretMetadata(
                        secretId,
                        SecretType.LOGIN_PASSWORD,
                        new SecretProfile(
                                title,
                                new SecretClassification(
                                        "development",
                                        "github",
                                        "github.com",
                                        "alice@example.com",
                                        Set.of("work")),
                                Set.of("work", "code"),
                                Map.of("project", "keystead")),
                        Instant.parse("2026-07-02T00:00:00Z"),
                        Instant.parse("2026-07-02T00:01:00Z"),
                        revision);
        EncryptedEnvelope envelope =
                new EncryptedEnvelope(
                        1,
                        "AES-256-GCM",
                        new KeyId("vault-key"),
                        new byte[] {1, 2, 3},
                        SecretRecordAad.encode(vaultId, metadata, revision),
                        new byte[] {7, 8, 9},
                        Instant.parse("2026-07-02T00:02:00Z"));
        return new EncryptedSecretRecord(vaultId, metadata, envelope, revision);
    }

    private static SecretId secretId(long suffix) {
        return new SecretId(new UUID(0L, suffix));
    }

    private static VaultId vaultId(long suffix) {
        return new VaultId(new UUID(0L, suffix));
    }

    private static DeletedSecretRecord deleted(
            @NonNull EncryptedSecretRecord record, long revision) {
        return deleted(record.metadata().id(), revision);
    }

    private static DeletedSecretRecord deleted(@NonNull SecretId secretId, long revision) {
        return deleted(header().vaultId(), secretId, revision);
    }

    private static DeletedSecretRecord deleted(
            @NonNull VaultId vaultId, @NonNull SecretId secretId, long revision) {
        return new DeletedSecretRecord(
                vaultId,
                secretId,
                SecretType.LOGIN_PASSWORD,
                revision,
                Instant.parse("2026-07-02T00:03:00Z"));
    }

    private @NonNull Path secretFile(@NonNull SecretId secretId) {
        return tempDir.resolve("secrets").resolve(secretId.value() + ".properties");
    }

    private @NonNull Path deletedFile(@NonNull SecretId secretId) {
        return tempDir.resolve("deleted").resolve(secretId.value() + ".properties");
    }

    private @NonNull String savedSecretRecordFileFor(
            @NonNull VaultId vaultId, @NonNull SecretId secretId) throws IOException {
        VaultStore setupStore = new FileVaultStore(tempDir);
        setupStore.saveSecretRecord(record(vaultId, secretId, "Wrong vault", 1L));
        String value = Files.readString(secretFile(secretId));
        Files.deleteIfExists(secretFile(secretId));
        return value;
    }

    private @NonNull String savedDeletedRecordFileFor(
            @NonNull VaultId vaultId, @NonNull SecretId secretId) throws IOException {
        VaultStore setupStore = new FileVaultStore(tempDir);
        setupStore.saveDeletedSecretRecord(deleted(vaultId, secretId, 1L));
        String value = Files.readString(deletedFile(secretId));
        Files.deleteIfExists(deletedFile(secretId));
        return value;
    }

    private static void await(@NonNull CountDownLatch latch) {
        try {
            if (!latch.await(5, TimeUnit.SECONDS)) {
                fail("timed out waiting for concurrent vault mutation");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            fail("interrupted while waiting for concurrent vault mutation");
        }
    }
}
