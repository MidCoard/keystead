package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;
import top.focess.keystead.crypto.CryptoAlgorithmRegistry;
import top.focess.keystead.model.KeyId;

class DeviceVaultKeyPackageTest {

    @Test
    void copiesAndRedactsEncryptedKeyMaterial() {
        byte[] encrypted = {1, 2, 3};
        DeviceVaultKeyPackage keyPackage =
                new DeviceVaultKeyPackage(
                        new KeyId("vault-key-2"),
                        CryptoAlgorithmRegistry.DEVICE_TINK_DEVICE_KEY_PACKAGE,
                        encrypted);
        encrypted[0] = 99;

        assertArrayEquals(new byte[] {1, 2, 3}, keyPackage.encryptedVaultKey());
        assertFalse(keyPackage.toString().contains("1, 2, 3"));
    }

    @Test
    void rejectsEmptyOrUnsupportedPackages() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new DeviceVaultKeyPackage(new KeyId("vault-key"), "RAW_RSA", new byte[] {1}));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new DeviceVaultKeyPackage(
                                new KeyId("vault-key"),
                                CryptoAlgorithmRegistry.DEVICE_TINK_DEVICE_KEY_PACKAGE,
                                new byte[0]));
    }
}
