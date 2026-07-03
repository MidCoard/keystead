package top.focess.keystead.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import top.focess.keystead.model.EncryptedEnvelope;
import top.focess.keystead.model.KeyId;

class CryptoProviderTest {

    @Test
    void tinkAeadCipherEncryptsAndDecryptsAesGcmPayloads() {
        AeadCipher cipher = new TinkAesGcmCipher();
        byte[] key = new byte[32];
        byte[] nonce = new byte[cipher.nonceSizeBytes()];
        new SecureRandom().nextBytes(key);
        new SecureRandom().nextBytes(nonce);
        byte[] aad = new byte[] {1, 2, 3};
        byte[] plaintext = new byte[] {4, 5, 6};

        byte[] ciphertext = cipher.encrypt(key, nonce, plaintext, aad);
        byte[] opened = cipher.decrypt(key, nonce, ciphertext, aad);

        assertEquals("AES-256-GCM", cipher.algorithm());
        assertArrayEquals(plaintext, opened);
        assertFalse(Arrays.equals(plaintext, ciphertext));
    }

    @Test
    void jdkAeadCipherEncryptsAndDecryptsChaCha20Poly1305Payloads() {
        AeadCipher cipher = new JdkChaCha20Poly1305Cipher();
        byte[] key = new byte[32];
        byte[] nonce = new byte[cipher.nonceSizeBytes()];
        new SecureRandom().nextBytes(key);
        new SecureRandom().nextBytes(nonce);
        byte[] aad = new byte[] {1, 2, 3};
        byte[] plaintext = new byte[] {4, 5, 6};

        byte[] ciphertext = cipher.encrypt(key, nonce, plaintext, aad);
        byte[] opened = cipher.decrypt(key, nonce, ciphertext, aad);

        assertEquals("CHACHA20-POLY1305", cipher.algorithm());
        assertArrayEquals(plaintext, opened);
        assertFalse(Arrays.equals(plaintext, ciphertext));
    }

    @Test
    void defaultCryptoServiceUsesInjectedCipherProvider() {
        DefaultCryptoService crypto =
                new DefaultCryptoService(new SecureRandom(), new TinkAesGcmCipher());

        try (VaultKey key = crypto.generateVaultKey(new KeyId("vault-key"))) {
            byte[] plaintext = new byte[] {9, 8, 7};
            byte[] aad = new byte[] {6, 5, 4};

            EncryptedEnvelope envelope =
                    crypto.encrypt(key, plaintext, aad, Instant.parse("2026-07-03T00:00:00Z"));
            byte[] opened = crypto.decrypt(key, envelope, aad);

            assertEquals("AES-256-GCM", envelope.algorithm());
            assertArrayEquals(plaintext, opened);
        }
    }

    @Test
    void defaultCryptoServiceCanDecryptSupportedNonDefaultAeadEnvelope() {
        DefaultCryptoService chachaCrypto =
                new DefaultCryptoService(new SecureRandom(), new JdkChaCha20Poly1305Cipher());
        DefaultCryptoService defaultCrypto = new DefaultCryptoService();

        try (VaultKey key = chachaCrypto.generateVaultKey(new KeyId("vault-key"))) {
            byte[] plaintext = new byte[] {9, 8, 7};
            byte[] aad = new byte[] {6, 5, 4};

            EncryptedEnvelope envelope =
                    chachaCrypto.encrypt(
                            key, plaintext, aad, Instant.parse("2026-07-03T00:00:00Z"));
            byte[] opened = defaultCrypto.decrypt(key, envelope, aad);

            assertEquals("CHACHA20-POLY1305", envelope.algorithm());
            assertArrayEquals(plaintext, opened);
        }
    }
}
