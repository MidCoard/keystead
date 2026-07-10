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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import top.focess.keystead.crypto.CryptoAlgorithmRegistry;
import top.focess.keystead.crypto.CryptoException;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.crypto.DeviceKeyPair;
import top.focess.keystead.crypto.VaultKey;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.memory.SecretDestroyedException;
import top.focess.keystead.model.KeyId;
import top.focess.keystead.model.SecretClassification;
import top.focess.keystead.model.SecretId;
import top.focess.keystead.model.SecretMetadata;
import top.focess.keystead.model.VaultHeader;
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
    void rotateVaultKeyReencryptsRecordsAndPersistsNewKeyId() {
        VaultService service = new DefaultVaultService(new FileVaultStore(tempDir), CLOCK);
        SecretId secretId;
        KeyId originalKeyId;
        try (VaultHandle vault = service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
            secretId = saveGitHubLogin(vault);
            originalKeyId = vault.vaultKeyId();
        }

        KeyId rotatedKeyId;
        try (VaultHandle rotated = service.rotateVaultKey(VAULT_ID, master())) {
            rotatedKeyId = rotated.vaultKeyId();
            assertNotEquals(originalKeyId, rotatedKeyId);
            rotated.withLogin(
                    secretId,
                    view -> view.withPassword(chars -> assertArrayEquals(chars("secret-password"), chars)));
        }

        try (VaultHandle reopened = service.openVault(VAULT_ID, master())) {
            assertEquals(rotatedKeyId, reopened.vaultKeyId());
            reopened.withLogin(
                    secretId,
                    view -> view.withUsername(chars -> assertArrayEquals(chars("alice@example.com"), chars)));
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
    void openVaultAcceptsApprovedSha512KdfHeader() {
        FileVaultStore store = new FileVaultStore(tempDir);
        DefaultCryptoService crypto = new DefaultCryptoService();
        VaultService service = new DefaultVaultService(store, crypto, CLOCK);
        KeyId keyId = new KeyId("vault-key-" + VAULT_ID.value());

        try (VaultKey key = crypto.generateVaultKey(keyId)) {
            byte[] salt = crypto.randomSalt();
            byte[] wrappedVaultKey =
                    crypto.wrapVaultKey(
                            key,
                            master(),
                            salt,
                            DefaultCryptoService.DEFAULT_KDF_ITERATIONS,
                            CryptoAlgorithmRegistry.KDF_PBKDF2_HMAC_SHA512);
            store.saveVaultHeader(
                    new VaultHeader(
                            VAULT_ID,
                            1,
                            CryptoAlgorithmRegistry.KDF_PBKDF2_HMAC_SHA512,
                            salt,
                            DefaultCryptoService.DEFAULT_KDF_ITERATIONS,
                            keyId,
                            wrappedVaultKey,
                            CLOCK.instant(),
                            CLOCK.instant()));
        }

        try (VaultHandle vault = service.openVault(VAULT_ID, master())) {
            assertEquals(VAULT_ID, vault.vaultId());
        }
    }

    @Test
    void vaultHandleCreatesContextBoundDeviceKeyPackage() {
        VaultService service = new DefaultVaultService(new FileVaultStore(tempDir), CLOCK);
        DefaultCryptoService crypto = new DefaultCryptoService();
        byte[] context = "vault:vault-1:device:laptop-1".getBytes(StandardCharsets.UTF_8);

        try (DeviceKeyPair device = crypto.generateDeviceKeyPair();
                VaultHandle vault =
                        service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
            byte[] packageBytes = vault.wrapVaultKeyForDevice(device.publicKey(), context);

            assertTrue(packageBytes.length > 0);
            assertDoesNotThrow(
                    () ->
                            crypto.unwrapVaultKeyFromDevicePackage(
                                            new KeyId("vault-key"),
                                            packageBytes,
                                            device.privateKey(),
                                            context)
                                    .close());
            assertThrows(
                    CryptoException.class,
                    () ->
                            crypto.unwrapVaultKeyFromDevicePackage(
                                    new KeyId("vault-key"),
                                    packageBytes,
                                    device.privateKey(),
                                    "wrong-context".getBytes(StandardCharsets.UTF_8)));
        }
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
    void updateLoginReplacesPayloadAndUsesNewRevision() {
        VaultService service = new DefaultVaultService(new FileVaultStore(tempDir), CLOCK);

        try (VaultHandle vault = service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
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
    void concurrentVaultHandlesSaveWithDistinctRevisions() throws Exception {
        VaultService service = new DefaultVaultService(new FileVaultStore(tempDir), CLOCK);
        ExecutorService executor = Executors.newFixedThreadPool(2);

        try (VaultHandle first = service.createVault(new CreateVaultRequest(VAULT_ID), master());
                VaultHandle second = service.openVault(VAULT_ID, master())) {
            CountDownLatch start = new CountDownLatch(1);
            Future<SecretId> firstSave =
                    executor.submit(
                            () -> {
                                await(start);
                                return saveLogin(first, "GitHub", "alice@example.com");
                            });
            Future<SecretId> secondSave =
                    executor.submit(
                            () -> {
                                await(start);
                                return saveLogin(second, "Google", "alice@gmail.com");
                            });

            start.countDown();

            assertNotNull(firstSave.get(5, TimeUnit.SECONDS));
            assertNotNull(secondSave.get(5, TimeUnit.SECONDS));
            assertEquals(
                    List.of(1L, 2L),
                    first.listSecrets().stream().map(SecretMetadata::revision).sorted().toList());
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void updateStructuredSecretReplacesFieldsAndUsesNewRevision() {
        VaultService service = new DefaultVaultService(new FileVaultStore(tempDir), CLOCK);

        try (VaultHandle vault = service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
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
        Files.writeString(secretFile, file + "\nenvelope.aad=" + b64("tampered-aad") + "\n");

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

    private static String b64(String value) {
        return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
}
