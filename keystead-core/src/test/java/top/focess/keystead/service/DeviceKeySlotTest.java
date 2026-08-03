package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.crypto.DeviceKeyPair;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.model.KeyId;
import top.focess.keystead.model.KeySlot;
import top.focess.keystead.model.SecretId;
import top.focess.keystead.model.SlotType;
import top.focess.keystead.store.VaultFileFormat;

class DeviceKeySlotTest {

    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-07-03T00:00:00Z"), ZoneOffset.UTC);

    @TempDir Path tempDir;

    private Path vaultFile(String name) {
        return tempDir.resolve(name + ".kv");
    }

    @Test
    void addDeviceKeyEnablesPassphraseLessUnlockAndKeepsPassphrase() throws Exception {
        DefaultCryptoService crypto = new DefaultCryptoService();
        DefaultVaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        byte[] context = "vault:add-device:device:laptop-1".getBytes(StandardCharsets.UTF_8);
        Path file = vaultFile("add-device");
        DeviceKeyPair device = crypto.generateDeviceKeyPair();
        try {
            SecretId secretId;
            try (VaultHandle source =
                    service.createVault(new CreateVaultRequest(file), masterPassword())) {
                secretId = saveLogin(source);
                source.addDeviceKey(device.publicKey(), context);
            }

            // The enrolled device can unlock the vault without the passphrase.
            try (VaultHandle viaDevice =
                    service.openVaultWithDeviceKey(file, privateKeyBytes(device), context)) {
                assertLoginReadable(viaDevice, secretId);
                assertEquals(1, viaDevice.listSecrets().size());
            }

            // The passphrase still unlocks the same vault (the DEK is unchanged).
            try (VaultHandle viaPassphrase = service.openVault(file, masterPassword())) {
                assertLoginReadable(viaPassphrase, secretId);
            }
        } finally {
            device.close();
        }
    }

    @Test
    void removeDeviceKeyRevokesPassphraseLessAccess() throws Exception {
        DefaultCryptoService crypto = new DefaultCryptoService();
        DefaultVaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        byte[] context = "vault:remove-device:device:laptop-1".getBytes(StandardCharsets.UTF_8);
        Path file = vaultFile("remove-device");
        DeviceKeyPair device = crypto.generateDeviceKeyPair();
        try {
            KeyId slotId;
            try (VaultHandle source =
                    service.createVault(new CreateVaultRequest(file), masterPassword())) {
                slotId = source.addDeviceKey(device.publicKey(), context);
            }

            // Revoke the device slot using the passphrase.
            try (VaultHandle viaPassphrase = service.openVault(file, masterPassword())) {
                viaPassphrase.removeDeviceKey(slotId);
            }

            // The device can no longer unlock the vault...
            assertThrows(
                    ValidationException.class,
                    () -> service.openVaultWithDeviceKey(file, privateKeyBytes(device), context));

            // ...but the passphrase still can.
            try (VaultHandle viaPassphrase = service.openVault(file, masterPassword())) {
                assertEquals(0, viaPassphrase.listSecrets().size());
            }
        } finally {
            device.close();
        }
    }

    @Test
    void removeDeviceKeyRejectsUnknownSlot() throws Exception {
        DefaultCryptoService crypto = new DefaultCryptoService();
        DefaultVaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        byte[] context = "vault:unknown-slot:device:laptop-1".getBytes(StandardCharsets.UTF_8);
        Path file = vaultFile("unknown-slot");
        DeviceKeyPair device = crypto.generateDeviceKeyPair();
        try {
            try (VaultHandle source =
                    service.createVault(new CreateVaultRequest(file), masterPassword())) {
                source.addDeviceKey(device.publicKey(), context);
                assertThrows(
                        ValidationException.class,
                        () -> source.removeDeviceKey(new KeyId("device-unknown")));
            }
        } finally {
            device.close();
        }
    }

    @Test
    void removeDeviceKeyRejectsRemovingLastSlot() throws Exception {
        DefaultCryptoService crypto = new DefaultCryptoService();
        DefaultVaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        byte[] context = "vault:last-slot:device:laptop-1".getBytes(StandardCharsets.UTF_8);
        Path file = vaultFile("last-slot");
        DeviceKeyPair device = crypto.generateDeviceKeyPair();
        try {
            // Provision a device-only vault (a single DEVICE slot, no passphrase).
            DeviceVaultKeyPackage keyPackage;
            try (VaultHandle source =
                    service.createVault(
                            new CreateVaultRequest(vaultFile("last-src")), masterPassword())) {
                keyPackage = source.wrapVaultKeyPackageForDevice(device.publicKey(), context);
            }
            try (VaultHandle ignored =
                    service.provisionVault(file, keyPackage, privateKeyBytes(device), context)) {
                // provisioning creates the device-only vault
            }

            KeyId deviceSlotId = deviceSlotId(file);
            try (VaultHandle viaDevice =
                    service.openVaultWithDeviceKey(file, privateKeyBytes(device), context)) {
                assertThrows(
                        ValidationException.class, () -> viaDevice.removeDeviceKey(deviceSlotId));
            }
        } finally {
            device.close();
        }
    }

    @Test
    void provisionedVaultCanInstallMasterPassphraseAndDiscardTransferSlot() throws Exception {
        DefaultCryptoService crypto = new DefaultCryptoService();
        DefaultVaultService service = new DefaultVaultService(new DefaultCryptoService(), CLOCK);
        byte[] context = "vault:restore:device:new-device".getBytes(StandardCharsets.UTF_8);
        Path file = vaultFile("restored-with-passphrase");
        DeviceKeyPair device = crypto.generateDeviceKeyPair();
        try {
            DeviceVaultKeyPackage keyPackage;
            top.focess.keystead.model.VaultFingerprint fingerprint;
            try (VaultHandle source =
                    service.createVault(
                            new CreateVaultRequest(vaultFile("restore-source")),
                            masterPassword())) {
                fingerprint = source.vaultFingerprint();
                keyPackage = source.wrapVaultKeyPackageForDevice(device.publicKey(), context);
            }

            SecretId restoredSecret;
            try (VaultHandle restored =
                    service.provisionVault(file, keyPackage, privateKeyBytes(device), context)) {
                restoredSecret = saveLogin(restored);
                restored.addPassphrase(restoredMasterPassword());
                restored.removeDeviceKey(deviceSlotId(file));
            }

            assertThrows(
                    ValidationException.class,
                    () -> service.openVaultWithDeviceKey(file, privateKeyBytes(device), context));
            try (VaultHandle reopened = service.openVault(file, restoredMasterPassword())) {
                assertEquals(fingerprint, reopened.vaultFingerprint());
                assertLoginReadable(reopened, restoredSecret);
            }
        } finally {
            device.close();
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

    private static void assertLoginReadable(VaultHandle vault, SecretId secretId) {
        vault.withLogin(
                secretId,
                view ->
                        view.withPassword(
                                password ->
                                        assertArrayEquals(
                                                "secret-password".toCharArray(), password)));
    }

    private static KeyId deviceSlotId(Path file) throws Exception {
        for (KeySlot slot : VaultFileFormat.readHeader(Files.readAllBytes(file)).slots()) {
            if (slot.slotType() == SlotType.DEVICE) {
                return slot.slotKeyId();
            }
        }
        throw new IllegalStateException("No device slot found in " + file);
    }

    private static char[] masterPassword() {
        return "correct horse battery staple".toCharArray();
    }

    private static char[] restoredMasterPassword() {
        return "new local vault master passphrase".toCharArray();
    }

    private static byte[] privateKeyBytes(DeviceKeyPair device) {
        final byte[][] output = new byte[1][];
        device.copyPrivateKey(bytes -> output[0] = bytes.clone());
        return output[0];
    }
}
