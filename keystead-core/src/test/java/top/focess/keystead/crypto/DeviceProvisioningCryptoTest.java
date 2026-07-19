package top.focess.keystead.crypto;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Field;
import java.security.SecureRandom;
import org.junit.jupiter.api.Test;
import top.focess.keystead.memory.SecretMemoryProvider;
import top.focess.keystead.model.KeyId;

class DeviceProvisioningCryptoTest {

    private final DefaultCryptoService crypto =
            new DefaultCryptoService(
                    new SecureRandom(), new TinkAesGcmCipher(), SecretMemoryProvider.heap());

    @Test
    void devicePublicKeyWrapsVaultKeyForMatchingPrivateKey() {
        try (DeviceKeyPair device = crypto.generateDeviceKeyPair();
                VaultKey vaultKey = crypto.generateVaultKey(new KeyId("vault-key"))) {
            byte[] context = "vault:vault-1:device:laptop-1".getBytes();

            byte[] encryptedVaultKey =
                    crypto.wrapVaultKeyForDevice(vaultKey, device.publicKey(), context);

            try (VaultKey opened =
                    crypto.unwrapVaultKeyFromDevicePackage(
                            new KeyId("vault-key"),
                            encryptedVaultKey,
                            privateKeyBytes(device),
                            context)) {
                assertArrayEquals(copy(vaultKey), copy(opened));
            }
        }
    }

    @Test
    void devicePackageRejectsWrongContextOrPrivateKey() {
        try (DeviceKeyPair device = crypto.generateDeviceKeyPair();
                DeviceKeyPair otherDevice = crypto.generateDeviceKeyPair();
                VaultKey vaultKey = crypto.generateVaultKey(new KeyId("vault-key"))) {
            byte[] context = "vault:vault-1:device:laptop-1".getBytes();
            byte[] encryptedVaultKey =
                    crypto.wrapVaultKeyForDevice(vaultKey, device.publicKey(), context);

            assertThrows(
                    CryptoException.class,
                    () ->
                            crypto.unwrapVaultKeyFromDevicePackage(
                                    new KeyId("vault-key"),
                                    encryptedVaultKey,
                                    privateKeyBytes(device),
                                    "vault:vault-1:device:phone-1".getBytes()));
            assertThrows(
                    CryptoException.class,
                    () ->
                            crypto.unwrapVaultKeyFromDevicePackage(
                                    new KeyId("vault-key"),
                                    encryptedVaultKey,
                                    privateKeyBytes(otherDevice),
                                    context));
        }
    }

    @Test
    void closingDeviceKeyPairWipesPrivateKeyMaterial() {
        DeviceKeyPair device = crypto.generateDeviceKeyPair();

        device.close();

        assertTrue(device.isClosed());
        assertArrayEquals(new byte[rawPrivateKey(device).length], rawPrivateKey(device));
        assertThrows(SecretKeyDestroyedException.class, () -> device.copyPrivateKey(bytes -> {}));
    }

    private static byte[] privateKeyBytes(DeviceKeyPair device) {
        final byte[][] output = new byte[1][];
        device.copyPrivateKey(bytes -> output[0] = bytes.clone());
        return output[0];
    }

    private static byte[] copy(VaultKey key) {
        final byte[][] output = new byte[1][];
        key.copyBytes(bytes -> output[0] = bytes.clone());
        return output[0];
    }

    private static byte[] rawPrivateKey(DeviceKeyPair device) {
        try {
            Field field = DeviceKeyPair.class.getDeclaredField("privateKey");
            field.setAccessible(true);
            Object memory = field.get(device);
            Field bytesField = memory.getClass().getDeclaredField("bytes");
            bytesField.setAccessible(true);
            return ((byte[]) bytesField.get(memory)).clone();
        } catch (ReflectiveOperationException e) {
            throw new AssertionError(e);
        }
    }
}
