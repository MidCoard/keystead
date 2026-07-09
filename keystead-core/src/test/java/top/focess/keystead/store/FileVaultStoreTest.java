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
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Assumptions;
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
