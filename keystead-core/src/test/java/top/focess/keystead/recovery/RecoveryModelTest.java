package top.focess.keystead.recovery;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import org.junit.jupiter.api.Test;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.model.KeyId;

class RecoveryModelTest {

    @Test
    void recoveryKitCopiesAndDestroysSecret() {
        byte[] source = bytes(32, (byte) 4);
        RecoveryKit kit = new RecoveryKit(1, "enrollment-1", 1L, source);
        source[0] = 99;
        byte[] first = kit.recoverySecret();
        assertEquals(4, first[0]);
        first[0] = 88;
        assertEquals(4, kit.recoverySecret()[0]);
        kit.close();
        assertTrue(kit.isClosed());
        assertThrows(IllegalStateException.class, kit::recoverySecret);
    }

    @Test
    void enrollmentMaterialOwnsSecretValuesAndRedactsText() {
        RecoveryKit kit = new RecoveryKit(1, "enrollment-1", 1L, bytes(32, (byte) 3));
        byte[] credential = bytes(32, (byte) 5);
        byte[] encryptedPrivateKey = bytes(80, (byte) 6);
        RecoveryPublicKey publicKey =
                new RecoveryPublicKey(
                        "enrollment-1",
                        1L,
                        DefaultCryptoService.DEVICE_KEY_ALGORITHM,
                        bytes(40, (byte) 7));
        RecoveryEnrollmentMaterial material =
                new RecoveryEnrollmentMaterial(kit, credential, publicKey, encryptedPrivateKey);
        credential[0] = 1;
        encryptedPrivateKey[0] = 1;
        assertEquals(5, material.accountCredential()[0]);
        assertEquals(6, material.encryptedPrivateKey()[0]);
        assertEquals("RecoveryEnrollmentMaterial(<redacted>)", material.toString());
        material.close();
        assertTrue(material.isClosed());
        assertTrue(kit.isClosed());
        assertThrows(IllegalStateException.class, material::accountCredential);
        assertThrows(IllegalStateException.class, material::encryptedPrivateKey);
    }

    @Test
    void publicKeyAndVaultPackageDefensivelyCopyBinaryFields() {
        byte[] publicBytes = bytes(40, (byte) 8);
        RecoveryPublicKey publicKey =
                new RecoveryPublicKey(
                        "enrollment-1", 2L, DefaultCryptoService.DEVICE_KEY_ALGORITHM, publicBytes);
        publicBytes[0] = 1;
        assertEquals(8, publicKey.publicKey()[0]);
        byte[] returnedPublic = publicKey.publicKey();
        returnedPublic[0] = 2;
        assertEquals(8, publicKey.publicKey()[0]);

        byte[] ciphertext = bytes(64, (byte) 9);
        RecoveryVaultKeyPackage keyPackage =
                new RecoveryVaultKeyPackage(
                        "user-1",
                        "vault-1",
                        new KeyId("vault-key-1"),
                        "enrollment-1",
                        2L,
                        DefaultCryptoService.DEVICE_KEY_ALGORITHM,
                        ciphertext);
        ciphertext[0] = 1;
        assertEquals(9, keyPackage.encryptedVaultKey()[0]);
        byte[] returnedCiphertext = keyPackage.encryptedVaultKey();
        returnedCiphertext[0] = 2;
        assertEquals(9, keyPackage.encryptedVaultKey()[0]);
        assertFalse(keyPackage.toString().contains(Arrays.toString(ciphertext)));
    }

    @Test
    void modelsRejectInvalidShape() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new RecoveryKit(2, "enrollment-1", 1L, bytes(32, (byte) 1)));
        assertThrows(
                IllegalArgumentException.class,
                () -> new RecoveryKit(1, "", 1L, bytes(32, (byte) 1)));
        assertThrows(
                IllegalArgumentException.class,
                () -> new RecoveryKit(1, "enrollment-1", 0L, bytes(32, (byte) 1)));
        assertThrows(
                IllegalArgumentException.class,
                () -> new RecoveryKit(1, "enrollment-1", 1L, bytes(31, (byte) 1)));
        assertThrows(
                IllegalArgumentException.class,
                () -> new RecoveryPublicKey("enrollment-1", 1L, "UNKNOWN", bytes(40, (byte) 1)));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        new RecoveryVaultKeyPackage(
                                "user-1",
                                "vault-1",
                                new KeyId("vault-key-1"),
                                "enrollment-1",
                                1L,
                                DefaultCryptoService.DEVICE_KEY_ALGORITHM,
                                new byte[0]));
    }

    private static byte[] bytes(int size, byte value) {
        byte[] bytes = new byte[size];
        Arrays.fill(bytes, value);
        return bytes;
    }
}
