package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import top.focess.keystead.crypto.CryptoAlgorithmRegistry;
import top.focess.keystead.crypto.CryptoException;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.crypto.DeviceKeyPair;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.model.KeyId;
import top.focess.keystead.model.SecretId;
import top.focess.keystead.model.SecurityLimits;
import top.focess.keystead.model.VaultFingerprint;

class ProvisionedVaultServiceTest {

    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-07-03T00:00:00Z"), ZoneOffset.UTC);

    @TempDir Path tempDir;

    private Path vaultFile(String name) {
        return tempDir.resolve(name + ".kv");
    }

    @Test
    void provisionedVaultUsesDevicePackageToImportAndReadSyncedSecrets() {
        DefaultCryptoService crypto = new DefaultCryptoService();
        DefaultVaultService sourceService =
                new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        DefaultVaultService targetService =
                new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        byte[] context = "vault:vault-1:device:laptop-1".getBytes(StandardCharsets.UTF_8);

        try (DeviceKeyPair device = crypto.generateDeviceKeyPair();
                VaultHandle source =
                        sourceService.createVault(
                                new CreateVaultRequest(vaultFile("source")), masterPassword())) {
            SecretId secretId = saveLogin(source);
            List<EncryptedSyncRecord> exported = source.exportRecordsSince(0);
            DeviceVaultKeyPackage keyPackage =
                    source.wrapVaultKeyPackageForDevice(device.publicKey(), context);

            try (VaultHandle target =
                    targetService.provisionVault(
                            vaultFile("target"), keyPackage, privateKeyBytes(device), context)) {
                assertEquals(1, target.importRecords(exported));
            }

            try (VaultHandle target =
                    targetService.openVaultWithDeviceKey(
                            vaultFile("target"), privateKeyBytes(device), context)) {
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
                new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        DefaultVaultService targetService =
                new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        byte[] context = "vault:vault-delete:device:laptop-1".getBytes(StandardCharsets.UTF_8);

        try (DeviceKeyPair device = crypto.generateDeviceKeyPair();
                VaultHandle source =
                        sourceService.createVault(
                                new CreateVaultRequest(vaultFile("delete-source")),
                                masterPassword())) {
            SecretId secretId = saveLogin(source);
            List<EncryptedSyncRecord> created = source.exportRecordsSince(0);
            DeviceVaultKeyPackage keyPackage =
                    source.wrapVaultKeyPackageForDevice(device.publicKey(), context);

            try (VaultHandle target =
                    targetService.provisionVault(
                            vaultFile("delete-target"),
                            keyPackage,
                            privateKeyBytes(device),
                            context)) {
                assertEquals(1, target.importRecords(created));
                assertEquals(1, target.listSecrets().size());
            }

            source.deleteSecret(secretId);
            List<EncryptedSyncRecord> deleted = source.exportRecordsSince(1);

            try (VaultHandle target =
                    targetService.openVaultWithDeviceKey(
                            vaultFile("delete-target"), privateKeyBytes(device), context)) {
                assertEquals(1, target.importRecords(deleted));
                assertEquals(0, target.listSecrets().size());
            }
        }
    }

    @Test
    void rawMetadataProvisioningPreservesCallerOwnedCiphertext() {
        DefaultCryptoService crypto = new DefaultCryptoService();
        DefaultVaultService sourceService =
                new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        DefaultVaultService targetService =
                new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        byte[] context = "vault:metadata:device:laptop-1".getBytes(StandardCharsets.UTF_8);

        try (DeviceKeyPair device = crypto.generateDeviceKeyPair();
                VaultHandle source =
                        sourceService.createVault(
                                new CreateVaultRequest(vaultFile("metadata-source")),
                                masterPassword())) {
            DeviceVaultKeyPackage keyPackage =
                    source.wrapVaultKeyPackageForDevice(device.publicKey(), context);
            byte[] expectedCiphertext = keyPackage.encryptedVaultKey();
            try (VaultHandle target =
                    targetService.provisionVault(
                            vaultFile("metadata-target"),
                            keyPackage,
                            privateKeyBytes(device),
                            context)) {
                assertEquals(source.vaultKeyId(), target.vaultKeyId());
                // Provisioning must not destroy the caller-owned package ciphertext.
                assertArrayEquals(expectedCiphertext, keyPackage.encryptedVaultKey());
            } finally {
                Arrays.fill(expectedCiphertext, (byte) 0);
            }
        }
    }

    @Test
    void provisionVaultRejectsInvalidKeyPackageArguments() {
        VaultFingerprint fingerprint =
                VaultFingerprint.fromHexString("00112233445566778899aabbccddeeff");
        KeyId keyId = new KeyId("vault-key");

        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new DeviceVaultKeyPackage(
                                fingerprint,
                                keyId,
                                CryptoAlgorithmRegistry.KDF_PBKDF2_HMAC_SHA256,
                                new byte[] {1}));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new DeviceVaultKeyPackage(
                                fingerprint,
                                keyId,
                                DefaultVaultService.DEVICE_KEY_PACKAGE_ALGORITHM,
                                new byte[0]));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new DeviceVaultKeyPackage(
                                fingerprint,
                                keyId,
                                DefaultVaultService.DEVICE_KEY_PACKAGE_ALGORITHM,
                                new byte[SecurityLimits.MAX_WRAPPED_KEY_PACKAGE_BYTES + 1]));
    }

    @Test
    void openVaultRejectsDeviceKeyProtectedVault() {
        DefaultCryptoService crypto = new DefaultCryptoService();
        DefaultVaultService sourceService =
                new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        DefaultVaultService targetService =
                new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        byte[] context = "vault:vault-mismatch:device:laptop-1".getBytes(StandardCharsets.UTF_8);

        try (DeviceKeyPair device = crypto.generateDeviceKeyPair();
                VaultHandle source =
                        sourceService.createVault(
                                new CreateVaultRequest(vaultFile("mismatch-source")),
                                masterPassword())) {
            DeviceVaultKeyPackage keyPackage =
                    source.wrapVaultKeyPackageForDevice(device.publicKey(), context);
            try (VaultHandle target =
                    targetService.provisionVault(
                            vaultFile("mismatch-target"),
                            keyPackage,
                            privateKeyBytes(device),
                            context)) {
                // provision a device-key-package-protected vault
            }
        }

        assertThrows(
                CryptoException.class,
                () -> targetService.openVault(vaultFile("mismatch-target"), masterPassword()));
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

    private static byte[] privateKeyBytes(DeviceKeyPair device) {
        final byte[][] output = new byte[1][];
        device.copyPrivateKey(bytes -> output[0] = bytes.clone());
        return output[0];
    }
}
