package top.focess.keystead.store;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.*;
import java.time.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.model.*;

class AtomicStoreMutationTest {
    @TempDir Path temp;
    private static final char[] PASSWORD = "atomic-store-fixture".toCharArray();
    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-09-01T00:00:00Z"), ZoneOffset.UTC);

    @Test
    void compoundFailureRestoresHeaderRevisionAndBothRecordMapsWithoutWriting() throws Exception {
        Path file = temp.resolve("vault");
        try (var store =
                OneFileVaultStore.create(new DefaultCryptoService(), file, PASSWORD, CLOCK)) {
            var metadata =
                    new SecretMetadata(
                            new SecretId(java.util.UUID.randomUUID()),
                            SecretType.SECURE_NOTE,
                            "existing",
                            java.util.Set.of(),
                            CLOCK.instant(),
                            CLOCK.instant(),
                            1);
            byte[] aad = SecretRecordAad.encode(store.vaultFingerprint(), metadata, 1);
            store.saveSecretRecord(
                    new EncryptedSecretRecord(
                            metadata,
                            store.crypto()
                                    .encrypt(
                                            store.vaultKey(), new byte[] {1}, aad, CLOCK.instant()),
                            1));
            var header = store.header();
            long revision = store.nextRevision();
            byte[] before = Files.readAllBytes(file);
            var id = new SecretId(java.util.UUID.randomUUID());
            assertThrows(
                    IllegalStateException.class,
                    () ->
                            store.commitMutation(
                                    next -> {
                                        store.saveVaultHeader(
                                                header.withUpdatedAt(
                                                        CLOCK.instant().plusSeconds(1)));
                                        store.saveDeletedSecretRecord(
                                                new DeletedSecretRecord(
                                                        id,
                                                        SecretType.SECURE_NOTE,
                                                        next,
                                                        CLOCK.instant()));
                                        store.deleteSecretRecord(metadata.secretId());
                                        throw new IllegalStateException("abort compound mutation");
                                    }));
            assertEquals(header, store.header());
            assertTrue(store.loadSecretRecord(metadata.secretId()).isPresent());
            assertEquals(revision, store.nextRevision());
            assertTrue(store.listDeletedSecretRecords().isEmpty());
            assertArrayEquals(before, Files.readAllBytes(file));
        }
    }

    @Test
    void failedWriteDoesNotLeakHeaderOrTombstoneIntoLaterCommit() throws Exception {
        Path dir = Files.createDirectory(temp.resolve("active"));
        Path parked = temp.resolve("parked");
        Path file = dir.resolve("vault");
        var id = new SecretId(java.util.UUID.randomUUID());
        try (var store =
                OneFileVaultStore.create(new DefaultCryptoService(), file, PASSWORD, CLOCK)) {
            var header = store.header();
            // Keep the sibling lock file in place: Windows does not allow moving its parent.
            Files.move(file, parked);
            Files.createDirectory(file);
            Path blocker = Files.writeString(file.resolve("blocker"), "force write failure");
            try {
                assertThrows(
                        StoreException.class,
                        () ->
                                store.saveDeletedSecretRecord(
                                        new DeletedSecretRecord(
                                                id, SecretType.SECURE_NOTE, 10, CLOCK.instant())));
                assertThrows(
                        StoreException.class,
                        () ->
                                store.saveVaultHeader(
                                        header.withUpdatedAt(CLOCK.instant().plusSeconds(1))));
            } finally {
                Files.delete(blocker);
                Files.delete(file);
                Files.move(parked, file);
            }
            assertTrue(store.listDeletedSecretRecords().isEmpty());
            assertEquals(1, store.nextRevision());
            assertEquals(header, store.header());
            store.recordRevision(2);
        }
        try (var reopened =
                OneFileVaultStore.open(new DefaultCryptoService(), file, PASSWORD, CLOCK)) {
            assertTrue(reopened.listDeletedSecretRecords().isEmpty());
            assertEquals(3, reopened.nextRevision());
        }
    }
}
