package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import top.focess.keystead.crypto.CryptoException;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.model.EncryptedEnvelope;
import top.focess.keystead.model.SecretId;

class FullVaultBackupServiceTest {

    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-07-31T00:00:00Z"), ZoneOffset.UTC);

    @TempDir Path tempDir;

    @Test
    void passwordProtectedBackupRestoresWithoutSourceVaultDeviceOrServer() throws Exception {
        DefaultVaultService vaults = new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        FullVaultBackupService backups =
                new FullVaultBackupService(new DefaultCryptoService(), CLOCK);
        Path sourceFile = tempDir.resolve("source.kvault");
        Path restoredFile = tempDir.resolve("restored.kvault");
        SecretId secretId;
        byte[] encodedBackup;

        try (VaultHandle source =
                vaults.createVault(sourceFile, chars("original-vault-passphrase"))) {
            try (SecretBuffer username = SecretBuffer.fromChars(chars("alice@example.com"));
                    SecretBuffer password = SecretBuffer.fromChars(chars("secret-password"))) {
                secretId =
                        source.saveLogin(
                                draft ->
                                        draft.title("GitHub")
                                                .username(username)
                                                .password(password));
            }
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            backups.export(source, chars("independent-backup-password"), output);
            encodedBackup = output.toByteArray();
        }

        Files.delete(sourceFile);
        assertFalse(
                new String(encodedBackup, StandardCharsets.ISO_8859_1).contains("secret-password"));

        try (VaultHandle restored =
                backups.restore(
                        restoredFile,
                        new ByteArrayInputStream(encodedBackup),
                        chars("independent-backup-password"),
                        chars("new-local-master-passphrase"))) {
            assertEquals(1, restored.listSecrets().size());
            restored.withLogin(
                    secretId,
                    view -> {
                        assertEquals("GitHub", view.metadata().title());
                        view.withPassword(
                                password -> assertArrayEquals(chars("secret-password"), password));
                    });
        }

        try (VaultHandle reopened =
                vaults.openVault(restoredFile, chars("new-local-master-passphrase"))) {
            assertEquals(1, reopened.listSecrets().size());
        }
        assertThrows(
                CryptoException.class,
                () -> vaults.openVault(restoredFile, chars("original-vault-passphrase")));
    }

    @Test
    void wrongBackupPasswordLeavesNoRestoredVault() throws Exception {
        byte[] encodedBackup = createEmptyBackup("correct-backup-password");
        Path restoredFile = tempDir.resolve("wrong-password.kvault");

        assertThrows(
                CryptoException.class,
                () ->
                        backupService()
                                .restore(
                                        restoredFile,
                                        new ByteArrayInputStream(encodedBackup),
                                        chars("wrong-backup-password"),
                                        chars("new-local-master-passphrase")));

        assertFalse(Files.exists(restoredFile));
    }

    @Test
    void tamperedCiphertextLeavesNoRestoredVault() throws Exception {
        FullBackupArchive original =
                FullBackupArchiveCodec.read(
                        new ByteArrayInputStream(createEmptyBackup("backup-password")));
        EncryptedEnvelope firstChunk = original.chunks().getFirst();
        byte[] ciphertext = firstChunk.ciphertext();
        ciphertext[ciphertext.length - 1] ^= 1;
        EncryptedEnvelope tamperedChunk =
                new EncryptedEnvelope(
                        firstChunk.version(),
                        firstChunk.algorithm(),
                        firstChunk.keyId(),
                        firstChunk.nonce(),
                        firstChunk.aad(),
                        ciphertext,
                        firstChunk.encryptedAt());
        List<EncryptedEnvelope> chunks = new ArrayList<>(original.chunks());
        chunks.set(0, tamperedChunk);
        FullBackupArchive tampered =
                new FullBackupArchive(
                        original.formatVersion(),
                        original.fingerprint(),
                        original.vaultKeyId(),
                        original.backupKdf(),
                        original.wrappedVaultKey(),
                        original.payloadDigest(),
                        chunks,
                        original.createdAt());
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        FullBackupArchiveCodec.write(tampered, output);
        Path restoredFile = tempDir.resolve("tampered.kvault");

        assertThrows(
                CryptoException.class,
                () ->
                        backupService()
                                .restore(
                                        restoredFile,
                                        new ByteArrayInputStream(output.toByteArray()),
                                        chars("backup-password"),
                                        chars("new-local-master-passphrase")));

        assertFalse(Files.exists(restoredFile));
    }

    @Test
    void occupiedRestoreTargetIsPreserved() throws Exception {
        byte[] encodedBackup = createEmptyBackup("backup-password");
        Path occupied = tempDir.resolve("occupied.kvault");
        byte[] originalBytes = "existing-vault-data".getBytes(StandardCharsets.UTF_8);
        Files.write(occupied, originalBytes);

        assertThrows(
                ValidationException.class,
                () ->
                        backupService()
                                .restore(
                                        occupied,
                                        new ByteArrayInputStream(encodedBackup),
                                        chars("backup-password"),
                                        chars("new-local-master-passphrase")));

        assertArrayEquals(originalBytes, Files.readAllBytes(occupied));
    }

    private byte[] createEmptyBackup(String backupPassword) {
        Path sourceFile = tempDir.resolve("source-" + backupPassword + ".kvault");
        try (VaultHandle source =
                vaultService().createVault(sourceFile, chars("original-vault-passphrase"))) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            backupService().export(source, chars(backupPassword), output);
            return output.toByteArray();
        }
    }

    private static FullVaultBackupService backupService() {
        return new FullVaultBackupService(new DefaultCryptoService(), CLOCK);
    }

    private static DefaultVaultService vaultService() {
        return new DefaultVaultService(new DefaultCryptoService(), CLOCK);
    }

    private static char[] chars(String value) {
        return value.toCharArray();
    }
}
