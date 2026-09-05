package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.model.*;

class ExplicitSyncResolutionTest {
    @TempDir Path temp;

    private char[] password() {
        return "sync-resolution-fixture".toCharArray();
    }

    @Test
    void resolvesEqualRevisionActiveConflictAndReopensWithChosenContent() throws Exception {
        var service = new DefaultVaultService();
        Path left = temp.resolve("left"), right = temp.resolve("right");
        SecretId id;
        try (var vault = service.createVault(left, password());
                var body = SecretBuffer.fromChars("initial".toCharArray())) {
            id = vault.saveSecureNote(d -> d.title("Note").body(body));
        }
        Files.copy(left, right);
        try (var a = service.openVault(left, password());
                var b = service.openVault(right, password());
                var local = SecretBuffer.fromChars("local".toCharArray());
                var remote = SecretBuffer.fromChars("remote".toCharArray())) {
            a.updateSecureNote(id, d -> d.title("Local").body(local));
            b.updateSecureNote(id, d -> d.title("Remote").body(remote));
            var selected = b.exportRecordsSince(0).getFirst();
            a.resolveSyncRecord(selected);
            assertTrue(a.listSecrets().getFirst().revision() > selected.revision());
            assertEquals(1, b.importRecords(a.exportRecordsSince(0)));
        }
        try (var reopened = service.openVault(left, password())) {
            reopened.withSecureNote(
                    id,
                    view ->
                            view.withBody(
                                    chars -> assertArrayEquals("remote".toCharArray(), chars)));
            assertEquals("Remote", reopened.listSecrets().getFirst().title());
        }
    }

    @Test
    void explicitResolutionSupportsDeletionAndResurrectionAndRejectsForgedContentKey()
            throws Exception {
        try (var vault = new DefaultVaultService().createVault(temp.resolve("vault"), password());
                var body = SecretBuffer.fromChars("secret".toCharArray())) {
            SecretId id = vault.saveSecureNote(d -> d.title("Note").body(body));
            var active = vault.exportRecordsSince(0).getFirst();
            vault.deleteSecret(id);
            var deletion = vault.exportRecordsSince(0).getFirst();
            vault.resolveSyncRecord(active);
            assertEquals(id, vault.listSecrets().getFirst().secretId());
            assertTrue(vault.listSecrets().getFirst().revision() > deletion.revision());
            var forged =
                    new EncryptedSyncRecord(
                            deletion.fingerprint(),
                            deletion.secretId(),
                            deletion.revision(),
                            deletion.secretType(),
                            deletion.encryptedProfile(),
                            deletion.envelope(),
                            true,
                            "forged");
            assertThrows(ValidationException.class, () -> vault.resolveSyncRecord(forged));
            assertEquals(1, vault.listSecrets().size());
            vault.resolveSyncRecord(deletion);
            assertTrue(vault.listSecrets().isEmpty());
            assertTrue(vault.exportRecordsSince(0).getFirst().revision() > deletion.revision());
        }
    }

    @Test
    void failedSaveDoesNotRemainVisibleOrPersistLater() throws Exception {
        Path dir = Files.createDirectory(temp.resolve("active")),
                parked = temp.resolve("parked"),
                file = dir.resolve("vault");
        try (var vault = new DefaultVaultService().createVault(file, password());
                var body = SecretBuffer.fromChars("body".toCharArray())) {
            // Keep the sibling lock file in place: Windows does not allow moving its parent.
            Files.move(file, parked);
            Files.createDirectory(file);
            Path blocker = Files.writeString(file.resolve("blocker"), "force write failure");
            try {
                assertThrows(
                        top.focess.keystead.store.StoreException.class,
                        () -> vault.saveSecureNote(d -> d.title("failed").body(body)));
            } finally {
                Files.delete(blocker);
                Files.delete(file);
                Files.move(parked, file);
            }
            assertTrue(vault.listSecrets().isEmpty());
            vault.saveSecureNote(d -> d.title("success").body(body));
            assertEquals(1, vault.listSecrets().getFirst().revision());
        }
        try (var vault = new DefaultVaultService().openVault(file, password())) {
            assertEquals(1, vault.listSecrets().size());
            assertEquals("success", vault.listSecrets().getFirst().title());
        }
    }
}
