package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import top.focess.keystead.crypto.CryptoException;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.memory.SecretDestroyedException;
import top.focess.keystead.model.SecretClassification;
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
                        assertEquals(
                                new SecretClassification(
                                        "development",
                                        "github",
                                        "alice@example.com",
                                        Set.of("work")),
                                view.metadata().classification());
                        assertEquals(
                                Map.of("project", "keystead"),
                                view.metadata().profile().attributes());
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
    void deleteLoginRemovesSecretFromVault() {
        VaultService service = new DefaultVaultService(new FileVaultStore(tempDir), CLOCK);
        SecretId secretId;

        try (VaultHandle vault = service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
            secretId = saveGitHubLogin(vault);
            vault.deleteSecret(secretId);

            assertEquals(List.of(), vault.listSecrets());
            assertThrows(ValidationException.class, () -> vault.withLogin(secretId, view -> {}));
        }
    }

    @Test
    void tamperedLoginMetadataCannotBeOpened() throws IOException {
        VaultService service = new DefaultVaultService(new FileVaultStore(tempDir), CLOCK);
        SecretId secretId;

        try (VaultHandle vault = service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
            secretId = saveGitHubLogin(vault);
        }

        Path secretFile = tempDir.resolve("secrets").resolve(secretId.value() + ".properties");
        String file = Files.readString(secretFile);
        Files.writeString(
                secretFile,
                file.replace(
                        "metadata.title=" + b64("GitHub"), "metadata.title=" + b64("Payroll")));

        try (VaultHandle vault = service.openVault(VAULT_ID, master())) {
            assertThrows(
                    CryptoException.class,
                    () -> vault.withLogin(secretId, view -> fail("tampered metadata opened")));
        }
    }

    @Test
    void tamperedLoginEnvelopeAadCannotBeOpened() throws IOException {
        VaultService service = new DefaultVaultService(new FileVaultStore(tempDir), CLOCK);
        SecretId secretId;

        try (VaultHandle vault = service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
            secretId = saveGitHubLogin(vault);
        }

        Path secretFile = tempDir.resolve("secrets").resolve(secretId.value() + ".properties");
        String file = Files.readString(secretFile);
        Files.writeString(
                secretFile,
                file.replaceAll("(?m)^envelope\\.aad=.*$", "envelope.aad=" + b64("tampered-aad")));

        try (VaultHandle vault = service.openVault(VAULT_ID, master())) {
            assertThrows(
                    CryptoException.class,
                    () -> vault.withLogin(secretId, view -> fail("tampered AAD opened")));
        }
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
                                    .classification(
                                            new SecretClassification(
                                                    "development",
                                                    "github",
                                                    "alice@example.com",
                                                    Set.of("work")))
                                    .attribute("project", "keystead")
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

    private static String b64(String value) {
        return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
}
