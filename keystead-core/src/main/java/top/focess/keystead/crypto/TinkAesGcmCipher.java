package top.focess.keystead.crypto;

import com.google.crypto.tink.aead.internal.InsecureNonceAesGcmJce;
import java.security.GeneralSecurityException;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.SecurityLimits;

public final class TinkAesGcmCipher implements AeadCipher {

    @Override
    public @NonNull String algorithm() {
        return JdkAesGcmCipher.ALGORITHM;
    }

    @Override
    public int nonceSizeBytes() {
        return InsecureNonceAesGcmJce.IV_SIZE_IN_BYTES;
    }

    @Override
    public byte @NonNull [] encrypt(
            byte @NonNull [] keyBytes,
            byte @NonNull [] nonce,
            byte @NonNull [] plaintext,
            byte @NonNull [] aad) {
        Objects.requireNonNull(keyBytes, "keyBytes");
        Objects.requireNonNull(nonce, "nonce");
        Objects.requireNonNull(plaintext, "plaintext");
        Objects.requireNonNull(aad, "aad");
        requireAes256Key(keyBytes);
        try {
            // Tink marks explicit-nonce AES-GCM as insecure because the caller must guarantee
            // nonce uniqueness; DefaultCryptoService owns nonce generation for Keystead.
            return new InsecureNonceAesGcmJce(keyBytes).encrypt(nonce, plaintext, aad);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Could not encrypt payload", e);
        }
    }

    @Override
    public byte @NonNull [] decrypt(
            byte @NonNull [] keyBytes,
            byte @NonNull [] nonce,
            byte @NonNull [] ciphertext,
            byte @NonNull [] aad) {
        Objects.requireNonNull(keyBytes, "keyBytes");
        Objects.requireNonNull(nonce, "nonce");
        Objects.requireNonNull(ciphertext, "ciphertext");
        Objects.requireNonNull(aad, "aad");
        requireAes256Key(keyBytes);
        try {
            return new InsecureNonceAesGcmJce(keyBytes).decrypt(nonce, ciphertext, aad);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Could not decrypt payload", e);
        }
    }

    private static void requireAes256Key(byte @NonNull [] keyBytes) {
        if (keyBytes.length != SecurityLimits.AES_256_KEY_BYTES) {
            throw new IllegalArgumentException("AES-256 key must be exactly 32 bytes");
        }
    }
}
