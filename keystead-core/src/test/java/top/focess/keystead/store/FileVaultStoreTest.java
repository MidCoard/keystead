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
        assertEquals("github.com", metadata.classification().software());
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
        SecretMetadata metadata =
                new SecretMetadata(
                        new SecretId(UUID.fromString("00000000-0000-0000-0000-000000000002")),
                        SecretType.LOGIN_PASSWORD,
                        new SecretProfile(
                                "GitHub",
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
