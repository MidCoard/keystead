package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.crypto.DeviceKeyPair;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.model.SecretId;
import top.focess.keystead.model.VaultId;
import top.focess.keystead.store.FileVaultStore;

class ProvisionedVaultServiceTest {

    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-07-03T00:00:00Z"), ZoneOffset.UTC);
    private static final VaultId VAULT_ID =
            new VaultId(UUID.fromString("30000000-0000-0000-0000-000000000001"));

    @TempDir Path tempDir;

    @Test
    void provisionedVaultUsesDevicePackageToImportAndReadSyncedSecrets() {
        DefaultCryptoService crypto = new DefaultCryptoService();
        DefaultVaultService sourceService =
                new DefaultVaultService(new FileVaultStore(tempDir.resolve("source")), CLOCK);
        DefaultVaultService targetService =
                new DefaultVaultService(new FileVaultStore(tempDir.resolve("target")), CLOCK);
        byte[] context = "vault:vault-1:device:laptop-1".getBytes(StandardCharsets.UTF_8);

        try (DeviceKeyPair device = crypto.generateDeviceKeyPair();
                VaultHandle source =
                        sourceService.createVault(
                                new CreateVaultRequest(VAULT_ID), masterPassword())) {
            SecretId secretId = saveLogin(source);
            List<EncryptedSyncRecord> exported = source.exportRecordsSince(0);
            byte[] packageBytes = source.wrapVaultKeyForDevice(device.publicKey(), context);

            try (VaultHandle target =
                    targetService.provisionVault(
                            VAULT_ID, packageBytes, device.privateKey(), context)) {
                assertEquals(1, target.importRecords(exported));
            }

            try (VaultHandle target =
                    targetService.openVaultWithDeviceKey(VAULT_ID, device.privateKey(), context)) {
                target.withLogin(
                        secretId,
                        view ->
                                view.withPassword(
                                        password ->
                                                assertArrayEquals(
                                                        "secret-password".toCharArray(),
                                                        password)));
            }
        }
    }

    @Test
    void provisionedVaultPullsTombstoneAndDeletesSyncedSecret() {
        DefaultCryptoService crypto = new DefaultCryptoService();
        DefaultVaultService sourceService =
                new DefaultVaultService(
                        new FileVaultStore(tempDir.resolve("delete-source")), CLOCK);
        DefaultVaultService targetService =
                new DefaultVaultService(
                        new FileVaultStore(tempDir.resolve("delete-target")), CLOCK);
        byte[] context = "vault:vault-delete:device:laptop-1".getBytes(StandardCharsets.UTF_8);

        try (DeviceKeyPair device = crypto.generateDeviceKeyPair();
                VaultHandle source =
                        sourceService.createVault(
                                new CreateVaultRequest(VAULT_ID), masterPassword())) {
            SecretId secretId = saveLogin(source);
            List<EncryptedSyncRecord> created = source.exportRecordsSince(0);
            byte[] packageBytes = source.wrapVaultKeyForDevice(device.publicKey(), context);

            try (VaultHandle target =
                    targetService.provisionVault(
                            VAULT_ID, packageBytes, device.privateKey(), context)) {
                assertEquals(1, target.importRecords(created));
                assertEquals(1, target.listSecrets().size());
            }

            source.deleteSecret(secretId);
            List<EncryptedSyncRecord> deleted = source.exportRecordsSince(1);

            try (VaultHandle target =
                    targetService.openVaultWithDeviceKey(VAULT_ID, device.privateKey(), context)) {
                assertEquals(1, target.importRecords(deleted));
                assertEquals(0, target.listSecrets().size());
            }
        }
    }

    private static SecretId saveLogin(VaultHandle vault) {
        try (SecretBuffer username = SecretBuffer.fromChars("alice@example.com".toCharArray());
                SecretBuffer password = SecretBuffer.fromChars("secret-password".toCharArray())) {
            return vault.saveLogin(
                    draft ->
                            draft.title("GitHub")
                                    .username(username)
                                    .password(password)
                                    .url("https://github.com"));
        }
    }

    private static char[] masterPassword() {
        return "correct horse battery staple".toCharArray();
    }
}
