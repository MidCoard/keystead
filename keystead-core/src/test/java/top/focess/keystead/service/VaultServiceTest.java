package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import top.focess.keystead.crypto.CryptoException;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.memory.SecretDestroyedException;
import top.focess.keystead.model.SecretId;
import top.focess.keystead.model.VaultId;
import top.focess.keystead.store.FileVaultStore;

class VaultServiceTest {

    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-07-02T00:00:00Z"), ZoneOffset.UTC);
    private static final VaultId VAULT_ID =
            new VaultId(UUID.fromString("10000000-0000-0000-0000-000000000001"));

    @TempDir Path tempDir;

    @Test
    void createSaveReopenAndReadLogin() {
        VaultService service = new DefaultVaultService(new FileVaultStore(tempDir), CLOCK);
        SecretId secretId;

        try (VaultHandle vault = service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
            secretId = saveGitHubLogin(vault);
        }

        try (VaultHandle vault = service.openVault(VAULT_ID, master())) {
            vault.withLogin(
                    secretId,
                    view -> {
                        assertEquals("GitHub", view.metadata().title());
                        assertEquals("https://github.com", view.url().orElseThrow());
                        view.withUsername(
                                chars -> assertArrayEquals(chars("alice@example.com"), chars));
                        view.withPassword(
                                chars -> assertArrayEquals(chars("secret-password"), chars));
                        view.withNotes(chars -> assertArrayEquals(chars("private note"), chars));
                    });
        }
    }

    @Test
    void wrongMasterPasswordCannotOpenVault() {
        VaultService service = new DefaultVaultService(new FileVaultStore(tempDir), CLOCK);

        try (VaultHandle ignored =
                service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
            // create vault
        }

        assertThrows(
                CryptoException.class, () -> service.openVault(VAULT_ID, chars("wrong-password")));
    }

    @Test
    void loginViewIsInvalidAfterCallbackReturns() {
        VaultService service = new DefaultVaultService(new FileVaultStore(tempDir), CLOCK);
        SecretId secretId;
        AtomicReference<LoginSecretView> captured = new AtomicReference<>();

        try (VaultHandle vault = service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
            secretId = saveGitHubLogin(vault);
            vault.withLogin(secretId, captured::set);
        }

        assertThrows(
                SecretDestroyedException.class,
                () -> captured.get().withPassword(chars -> fail("view should be closed")));
    }

    @Test
    void saveLoginRequiresTitleAndPassword() {
        VaultService service = new DefaultVaultService(new FileVaultStore(tempDir), CLOCK);

        try (VaultHandle vault = service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
            assertThrows(
                    ValidationException.class,
                    () ->
                            vault.saveLogin(
                                    draft ->
                                            draft.password(
                                                    SecretBuffer.fromChars(
                                                            chars("secret-password")))));
            assertThrows(
                    ValidationException.class,
                    () -> vault.saveLogin(draft -> draft.title("GitHub")));
        }
    }

    @Test
    void persistedLoginRecordDoesNotContainPlaintextSecretValues() throws IOException {
        VaultService service = new DefaultVaultService(new FileVaultStore(tempDir), CLOCK);
        SecretId secretId;

        try (VaultHandle vault = service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
            secretId = saveGitHubLogin(vault);
        }

        String file =
                Files.readString(
                        tempDir.resolve("secrets").resolve(secretId.value() + ".properties"));
        assertFalse(file.contains("alice@example.com"));
        assertFalse(file.contains("secret-password"));
        assertFalse(file.contains("private note"));
    }

    @Test
    void closingVaultHandleRejectsFurtherOperations() {
        VaultService service = new DefaultVaultService(new FileVaultStore(tempDir), CLOCK);
        VaultHandle vault = service.createVault(new CreateVaultRequest(VAULT_ID), master());

        vault.close();

        assertTrue(vault.isClosed());
        assertThrows(IllegalStateException.class, () -> saveGitHubLogin(vault));
    }

    private static SecretId saveGitHubLogin(VaultHandle vault) {
        try (SecretBuffer username = SecretBuffer.fromChars(chars("alice@example.com"));
                SecretBuffer password = SecretBuffer.fromChars(chars("secret-password"));
                SecretBuffer notes = SecretBuffer.fromChars(chars("private note"))) {
            return vault.saveLogin(
                    draft ->
                            draft.title("GitHub")
                                    .tag("work")
                                    .username(username)
                                    .password(password)
                                    .url("https://github.com")
                                    .notes(notes));
        }
    }

    private static char[] master() {
        return chars("correct horse battery staple");
    }

    private static char[] chars(String value) {
        return value.toCharArray();
    }
}
