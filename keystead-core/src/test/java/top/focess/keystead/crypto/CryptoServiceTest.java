package top.focess.keystead.crypto;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Field;
import java.time.Instant;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import top.focess.keystead.model.EncryptedEnvelope;
import top.focess.keystead.model.KeyId;

class CryptoServiceTest {

    private final DefaultCryptoService crypto = new DefaultCryptoService();

    @Test
    void encryptDecryptRoundTripReturnsPlaintext() {
        try (VaultKey key = crypto.generateVaultKey(new KeyId("vault-key"))) {
            byte[] plaintext = new byte[] {1, 2, 3};
            byte[] aad = new byte[] {4, 5, 6};

            EncryptedEnvelope envelope =
                    crypto.encrypt(key, plaintext, aad, Instant.parse("2026-07-02T00:00:00Z"));
            byte[] opened = crypto.decrypt(key, envelope, aad);

            assertArrayEquals(plaintext, opened);
            assertFalse(Arrays.equals(plaintext, envelope.ciphertext()));
        }
    }

    @Test
    void decryptRejectsChangedAad() {
        try (VaultKey key = crypto.generateVaultKey(new KeyId("vault-key"))) {
            EncryptedEnvelope envelope =
                    crypto.encrypt(
                            key,
                            new byte[] {1, 2, 3},
                            new byte[] {4, 5, 6},
                            Instant.parse("2026-07-02T00:00:00Z"));

            assertThrows(
                    CryptoException.class,
                    () -> crypto.decrypt(key, envelope, new byte[] {4, 5, 7}));
        }
    }

    @Test
    void encryptingSamePlaintextTwiceUsesDifferentNonceAndCiphertext() {
        try (VaultKey key = crypto.generateVaultKey(new KeyId("vault-key"))) {
            byte[] plaintext = new byte[] {1, 2, 3};
            byte[] aad = new byte[] {4, 5, 6};

            EncryptedEnvelope first =
                    crypto.encrypt(key, plaintext, aad, Instant.parse("2026-07-02T00:00:00Z"));
            EncryptedEnvelope second =
                    crypto.encrypt(key, plaintext, aad, Instant.parse("2026-07-02T00:00:00Z"));

            assertFalse(Arrays.equals(first.nonce(), second.nonce()));
            assertFalse(Arrays.equals(first.ciphertext(), second.ciphertext()));
        }
    }

    @Test
    void decryptRejectsEnvelopeEncryptedUnderDifferentKeyId() {
        try (VaultKey encryptingKey = crypto.generateVaultKey(new KeyId("vault-key-a"));
                VaultKey wrongKey = crypto.generateVaultKey(new KeyId("vault-key-b"))) {
            EncryptedEnvelope envelope =
                    crypto.encrypt(
                            encryptingKey,
                            new byte[] {1, 2, 3},
                            new byte[] {4, 5, 6},
                            Instant.parse("2026-07-02T00:00:00Z"));

            CryptoException ex =
                    assertThrows(
                            CryptoException.class,
                            () -> crypto.decrypt(wrongKey, envelope, new byte[] {4, 5, 6}));

            assertNull(ex.getCause(), "wrong key id should be rejected before GCM is attempted");
            assertTrue(ex.getMessage().toLowerCase().contains("key id"));
        }
    }

    @Test
    void wrongMasterPasswordCannotUnwrapVaultKey() {
        try (VaultKey key = crypto.generateVaultKey(new KeyId("vault-key"))) {
            byte[] salt = crypto.randomSalt();
            byte[] wrapped =
                    crypto.wrapVaultKey(
                            key, new char[] {'c', 'o', 'r', 'r', 'e', 'c', 't'}, salt, 120_000);

            assertThrows(
                    CryptoException.class,
                    () ->
                            crypto.unwrapVaultKey(
                                    new KeyId("vault-key"),
                                    wrapped,
                                    new char[] {'w', 'r', 'o', 'n', 'g'},
                                    salt,
                                    120_000));
        }
    }

    @Test
    void closingVaultKeyWipesOwnedBytes() {
        VaultKey key = crypto.generateVaultKey(new KeyId("vault-key"));

        key.close();

        assertTrue(key.isClosed());
        assertArrayEquals(new byte[32], rawKeyBytes(key));
        assertThrows(
                SecretKeyDestroyedException.class,
                () -> key.copyBytes(bytes -> fail("closed key should not be readable")));
    }

    private static byte[] rawKeyBytes(VaultKey key) {
        try {
            Field field = VaultKey.class.getDeclaredField("keyBytes");
            field.setAccessible(true);
            return ((byte[]) field.get(key)).clone();
        } catch (ReflectiveOperationException e) {
            throw new AssertionError(e);
        }
    }
}
