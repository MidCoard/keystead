package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import top.focess.keystead.crypto.CryptoException;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.crypto.DeviceKeyPair;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.memory.SecretDestroyedException;
import top.focess.keystead.model.KeyId;
import top.focess.keystead.model.SecretClassification;
import top.focess.keystead.model.SecretId;
import top.focess.keystead.model.SecretMetadata;

class VaultServiceTest {

    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-07-02T00:00:00Z"), ZoneOffset.UTC);

    @TempDir Path tempDir;

    private Path vaultFile() {
        return tempDir.resolve("vault.kv");
    }

    @Test
    void createSaveReopenAndReadLogin() {
        VaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        SecretId secretId;

        try (VaultHandle vault = service.createVault(vaultFile(), master())) {
            secretId = saveGitHubLogin(vault);
        }

        try (VaultHandle vault = service.openVault(vaultFile(), master())) {
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
    void rotateVaultKeyReencryptsRecordsAndPersistsNewKeyId() {
        VaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        SecretId secretId;
        KeyId originalKeyId;
        try (VaultHandle vault = service.createVault(vaultFile(), master())) {
            secretId = saveGitHubLogin(vault);
            originalKeyId = vault.vaultKeyId();
        }

        KeyId rotatedKeyId;
        try (VaultHandle rotated = service.rotateVaultKey(vaultFile(), master())) {
            rotatedKeyId = rotated.vaultKeyId();
            assertNotEquals(originalKeyId, rotatedKeyId);
            rotated.withLogin(
                    secretId,
                    view ->
                            view.withPassword(
                                    chars -> assertArrayEquals(chars("secret-password"), chars)));
        }

        try (VaultHandle reopened = service.openVault(vaultFile(), master())) {
            assertEquals(rotatedKeyId, reopened.vaultKeyId());
            reopened.withLogin(
                    secretId,
                    view ->
                            view.withUsername(
                                    chars -> assertArrayEquals(chars("alice@example.com"), chars)));
        }
    }

    @Test
    void wrongMasterPasswordCannotOpenVault() {
        VaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);

        try (VaultHandle ignored = service.createVault(vaultFile(), master())) {
            // create vault
        }

        assertThrows(
                CryptoException.class,
                () -> service.openVault(vaultFile(), chars("wrong-password")));
    }

    @Test
    void openVaultWithDeviceKeyRejectsPasswordProtectedVault() {
        VaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);

        try (VaultHandle ignored = service.createVault(vaultFile(), master())) {
            // create a master-password-protected vault
        }

        assertThrows(
                ValidationException.class,
                () -> service.openVaultWithDeviceKey(vaultFile(), new byte[32], new byte[16]));
    }

    @Test
    void vaultHandleCreatesContextBoundDeviceKeyPackage() {
        VaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        DefaultCryptoService crypto = new DefaultCryptoService();
        byte[] context = "vault:vault-1:device:laptop-1".getBytes(StandardCharsets.UTF_8);

        try (DeviceKeyPair device = crypto.generateDeviceKeyPair();
                VaultHandle vault = service.createVault(vaultFile(), master())) {
            byte[] packageBytes = vault.wrapVaultKeyForDevice(device.publicKey(), context);

            assertTrue(packageBytes.length > 0);
            assertDoesNotThrow(
                    () ->
                            crypto.unwrapVaultKeyFromDevicePackage(
                                            new KeyId("vault-key"),
                                            packageBytes,
                                            privateKeyBytes(device),
                                            context)
                                    .close());
            assertThrows(
                    CryptoException.class,
                    () ->
                            crypto.unwrapVaultKeyFromDevicePackage(
                                    new KeyId("vault-key"),
                                    packageBytes,
                                    privateKeyBytes(device),
                                    "wrong-context".getBytes(StandardCharsets.UTF_8)));
        }
    }

    @Test
    void loginViewIsInvalidAfterCallbackReturns() {
        VaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        SecretId secretId;
        AtomicReference<LoginSecretView> captured = new AtomicReference<>();

        try (VaultHandle vault = service.createVault(vaultFile(), master())) {
            secretId = saveGitHubLogin(vault);
            vault.withLogin(secretId, captured::set);
        }

        assertThrows(
                SecretDestroyedException.class,
                () -> captured.get().withPassword(chars -> fail("view should be closed")));
    }

    @Test
    void saveLoginRequiresTitleAndPassword() {
        VaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);

        try (VaultHandle vault = service.createVault(vaultFile(), master())) {
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
        VaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);

        try (VaultHandle vault = service.createVault(vaultFile(), master())) {
            saveGitHubLogin(vault);
        }

        byte[] bytes = Files.readAllBytes(vaultFile());
        String vaultContents = new String(bytes, StandardCharsets.UTF_8);
        assertFalse(vaultContents.contains("alice@example.com"));
        assertFalse(vaultContents.contains("secret-password"));
        assertFalse(vaultContents.contains("private note"));
    }

    @Test
    void deleteLoginRemovesSecretFromVault() {
        VaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        SecretId secretId;

        try (VaultHandle vault = service.createVault(vaultFile(), master())) {
            secretId = saveGitHubLogin(vault);
            vault.deleteSecret(secretId);

            assertEquals(List.of(), vault.listSecrets());
            assertThrows(ValidationException.class, () -> vault.withLogin(secretId, view -> {}));
        }
    }

    @Test
    void updateLoginReplacesPayloadAndUsesNewRevision() {
        VaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);

        try (VaultHandle vault = service.createVault(vaultFile(), master())) {
            SecretId secretId = saveGitHubLogin(vault);

            try (SecretBuffer username = SecretBuffer.fromChars(chars("alice@example.com"));
                    SecretBuffer password = SecretBuffer.fromChars(chars("rotated-password"))) {
                vault.updateLogin(
                        secretId,
                        draft ->
                                draft.title("GitHub")
                                        .classification(
                                                new SecretClassification(
                                                        "development",
                                                        "github",
                                                        "alice@example.com",
                                                        Set.of("work")))
                                        .username(username)
                                        .password(password)
                                        .url("https://github.com"));
            }

            assertEquals(2L, vault.listSecrets().getFirst().revision());
            vault.withLogin(
                    secretId,
                    view -> {
                        assertEquals("GitHub", view.metadata().title());
                        view.withPassword(
                                password -> assertArrayEquals(chars("rotated-password"), password));
                    });
            assertEquals(1, vault.exportRecordsSince(1).size());
            assertEquals(2L, vault.exportRecordsSince(1).getFirst().revision());
        }
    }

    @Test
    void concurrentSavesThroughOneHandleGetDistinctRevisions() throws Exception {
        VaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        ExecutorService executor = Executors.newFixedThreadPool(2);

        try (VaultHandle vault = service.createVault(vaultFile(), master())) {
            CountDownLatch start = new CountDownLatch(1);
            Future<SecretId> firstSave =
                    executor.submit(
                            () -> {
                                await(start);
                                return saveLogin(vault, "GitHub", "alice@example.com");
                            });
            Future<SecretId> secondSave =
                    executor.submit(
                            () -> {
                                await(start);
                                return saveLogin(vault, "Google", "alice@gmail.com");
                            });

            start.countDown();

            assertNotNull(firstSave.get(5, TimeUnit.SECONDS));
            assertNotNull(secondSave.get(5, TimeUnit.SECONDS));
            assertEquals(
                    List.of(1L, 2L),
                    vault.listSecrets().stream().map(SecretMetadata::revision).sorted().toList());
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void updateStructuredSecretReplacesFieldsAndUsesNewRevision() {
        VaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);

        try (VaultHandle vault = service.createVault(vaultFile(), master())) {
            SecretId secretId;
            try (SecretBuffer token = SecretBuffer.fromChars(chars("ghp_old"))) {
                secretId =
                        vault.saveSecret(
                                top.focess.keystead.model.SecretType.API_TOKEN,
                                draft -> draft.title("GitHub token").field("token", token));
            }

            try (SecretBuffer token = SecretBuffer.fromChars(chars("ghp_new"))) {
                vault.updateSecret(
                        secretId,
                        draft ->
                                draft.title("GitHub token")
                                        .classification(
                                                new SecretClassification(
                                                        "development",
                                                        "github",
                                                        "alice@example.com"))
                                        .field("token", token));
            }

            assertEquals(2L, vault.listSecrets().getFirst().revision());
            vault.withSecret(
                    secretId,
                    view ->
                            view.withField(
                                    "token", token -> assertArrayEquals(chars("ghp_new"), token)));
            assertEquals(1, vault.exportRecordsSince(1).size());
            assertEquals(2L, vault.exportRecordsSince(1).getFirst().revision());
        }
    }

    @Test
    void closingVaultHandleRejectsFurtherOperations() {
        VaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        VaultHandle vault = service.createVault(vaultFile(), master());

        vault.close();

        assertTrue(vault.isClosed());
        assertThrows(IllegalStateException.class, () -> saveGitHubLogin(vault));
        assertThrows(
                IllegalStateException.class,
                () -> vault.wrapVaultKeyForDevice(new byte[] {1, 2, 3}, new byte[] {4, 5, 6}));
    }

    private static SecretId saveGitHubLogin(VaultHandle vault) {
        return saveLogin(vault, "GitHub", "alice@example.com");
    }

    private static SecretId saveLogin(VaultHandle vault, String title, String account) {
        try (SecretBuffer username = SecretBuffer.fromChars(chars("alice@example.com"));
                SecretBuffer password = SecretBuffer.fromChars(chars("secret-password"));
                SecretBuffer notes = SecretBuffer.fromChars(chars("private note"))) {
            return vault.saveLogin(
                    draft ->
                            draft.title(title)
                                    .classification(
                                            new SecretClassification(
                                                    "development",
                                                    title.toLowerCase(),
                                                    account,
                                                    Set.of("work")))
                                    .attribute("project", "keystead")
                                    .tag("work")
                                    .username(username)
                                    .password(password)
                                    .url("https://github.com")
                                    .notes(notes));
        }
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(5, TimeUnit.SECONDS)) {
                fail("timed out waiting for concurrent vault save");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            fail("interrupted while waiting for concurrent vault save");
        }
    }

    private static char[] master() {
        return chars("correct horse battery staple");
    }

    private static char[] chars(String value) {
        return value.toCharArray();
    }

    private static byte[] privateKeyBytes(DeviceKeyPair device) {
        final byte[][] output = new byte[1][];
        device.copyPrivateKey(bytes -> output[0] = bytes.clone());
        return output[0];
    }
}
