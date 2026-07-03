package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.memory.SecretDestroyedException;
import top.focess.keystead.model.SecretClassification;
import top.focess.keystead.model.SecretFieldSchema;
import top.focess.keystead.model.SecretId;
import top.focess.keystead.model.SecretType;
import top.focess.keystead.model.SecretTypeSchema;
import top.focess.keystead.model.VaultId;
import top.focess.keystead.store.FileVaultStore;

class StructuredSecretServiceTest {

    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-07-03T00:00:00Z"), ZoneOffset.UTC);
    private static final VaultId VAULT_ID =
            new VaultId(UUID.fromString("40000000-0000-0000-0000-000000000001"));

    @TempDir Path tempDir;

    @Test
    void createSaveReopenAndReadSshKey() {
        VaultService service = new DefaultVaultService(new FileVaultStore(tempDir), CLOCK);
        SecretId secretId;

        try (VaultHandle vault = service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
            secretId = saveSshKey(vault);
        }

        try (VaultHandle vault = service.openVault(VAULT_ID, master())) {
            vault.withSecret(
                    secretId,
                    view -> {
                        assertEquals(SecretType.SSH_KEY, view.metadata().type());
                        assertEquals("Work SSH", view.metadata().title());
                        assertEquals(
                                new SecretClassification(
                                        "development", "ssh", "git@example.com", Set.of("work")),
                                view.metadata().classification());
                        assertEquals(
                                Map.of("host", "github.com"),
                                view.metadata().profile().attributes());
                        assertEquals(
                                Set.of("publicKey", "privateKey", "passphrase"), view.fieldNames());
                        view.withField(
                                "privateKey",
                                chars ->
                                        assertArrayEquals(
                                                chars("-----BEGIN OPENSSH PRIVATE KEY-----"),
                                                chars));
                    });
        }
    }

    @Test
    void structuredSecretSupportsAllGeneralSecretTypes() {
        VaultService service = new DefaultVaultService(new FileVaultStore(tempDir), CLOCK);

        try (VaultHandle vault = service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
            for (SecretType type :
                    Set.of(
                            SecretType.SSH_KEY,
                            SecretType.API_TOKEN,
                            SecretType.GPG_KEY,
                            SecretType.MFA_SECRET,
                            SecretType.CERTIFICATE,
                            SecretType.GENERIC_SECRET)) {
                SecretId secretId =
                        vault.saveSecret(
                                type,
                                draft -> {
                                    draft.title(type.name());
                                    for (String fieldName : validFieldNames(type)) {
                                        draft.field(
                                                fieldName,
                                                SecretBuffer.fromChars(chars("encrypted payload")));
                                    }
                                });

                vault.withSecret(
                        secretId,
                        view -> {
                            assertEquals(type, view.metadata().type());
                            view.withField(
                                    validFieldNames(type).iterator().next(),
                                    chars -> assertArrayEquals(chars("encrypted payload"), chars));
                        });
            }
        }
    }

    @Test
    void structuredSecretViewIsInvalidAfterCallbackReturns() {
        VaultService service = new DefaultVaultService(new FileVaultStore(tempDir), CLOCK);
        AtomicReference<StructuredSecretView> captured = new AtomicReference<>();

        try (VaultHandle vault = service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
            SecretId secretId = saveSshKey(vault);
            vault.withSecret(secretId, captured::set);
        }

        assertThrows(
                SecretDestroyedException.class,
                () -> captured.get().withField("privateKey", chars -> {}));
    }

    @Test
    void saveStructuredSecretRequiresTitleAndField() {
        VaultService service = new DefaultVaultService(new FileVaultStore(tempDir), CLOCK);

        try (VaultHandle vault = service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
            assertThrows(
                    ValidationException.class,
                    () ->
                            vault.saveSecret(
                                    SecretType.API_TOKEN,
                                    draft ->
                                            draft.field(
                                                    "token",
                                                    SecretBuffer.fromChars(chars("token")))));
            assertThrows(
                    ValidationException.class,
                    () ->
                            vault.saveSecret(
                                    SecretType.API_TOKEN,
                                    draft -> draft.title("GitHub API token")));
        }
    }

    @Test
    void saveStructuredSecretEnforcesTypeSchemaFields() {
        VaultService service = new DefaultVaultService(new FileVaultStore(tempDir), CLOCK);

        try (VaultHandle vault = service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
            assertThrows(
                    ValidationException.class,
                    () ->
                            vault.saveSecret(
                                    SecretType.SSH_KEY,
                                    draft ->
                                            draft.title("Invalid SSH")
                                                    .field(
                                                            "value",
                                                            SecretBuffer.fromChars(
                                                                    chars("not-an-ssh-field")))));
            assertThrows(
                    ValidationException.class,
                    () ->
                            vault.saveSecret(
                                    SecretType.API_TOKEN,
                                    draft ->
                                            draft.title("Missing token")
                                                    .field(
                                                            "notes",
                                                            SecretBuffer.fromChars(
                                                                    chars("optional only")))));
        }
    }

    @Test
    void persistedStructuredSecretDoesNotContainPlaintextFields() throws IOException {
        VaultService service = new DefaultVaultService(new FileVaultStore(tempDir), CLOCK);
        SecretId secretId;

        try (VaultHandle vault = service.createVault(new CreateVaultRequest(VAULT_ID), master())) {
            secretId = saveSshKey(vault);
        }

        String file =
                Files.readString(
                        tempDir.resolve("secrets").resolve(secretId.value() + ".properties"));
        assertFalse(file.contains("-----BEGIN OPENSSH PRIVATE KEY-----"));
        assertFalse(file.contains("private-passphrase"));
    }

    private static SecretId saveSshKey(VaultHandle vault) {
        try (SecretBuffer publicKey = SecretBuffer.fromChars(chars("ssh-ed25519 AAAA"));
                SecretBuffer privateKey =
                        SecretBuffer.fromChars(chars("-----BEGIN OPENSSH PRIVATE KEY-----"));
                SecretBuffer passphrase = SecretBuffer.fromChars(chars("private-passphrase"))) {
            return vault.saveSecret(
                    SecretType.SSH_KEY,
                    draft ->
                            draft.title("Work SSH")
                                    .classification(
                                            new SecretClassification(
                                                    "development",
                                                    "ssh",
                                                    "git@example.com",
                                                    Set.of("work")))
                                    .attribute("host", "github.com")
                                    .tag("developer")
                                    .field("publicKey", publicKey)
                                    .field("privateKey", privateKey)
                                    .field("passphrase", passphrase));
        }
    }

    private static char[] master() {
        return chars("correct horse battery staple");
    }

    private static char[] chars(String value) {
        return value.toCharArray();
    }

    private static Set<String> validFieldNames(SecretType type) {
        SecretTypeSchema schema = SecretTypeSchema.forType(type);
        if (schema.allowsCustomFields()) {
            return Set.of("value");
        }
        return schema.fields().stream()
                .filter(SecretFieldSchema::required)
                .map(SecretFieldSchema::name)
                .collect(java.util.stream.Collectors.toCollection(java.util.LinkedHashSet::new));
    }
}
