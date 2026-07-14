package top.focess.keystead.crypto;

import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.SecurityLimits;

public final class JdkAesGcmCipher implements AeadCipher {

    public static final String ALGORITHM = "AES-256-GCM";

    private static final int NONCE_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;

    @Override
    public @NonNull String algorithm() {
        return ALGORITHM;
    }

    @Override
    public int nonceSizeBytes() {
        return NONCE_BYTES;
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
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(
                    Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(keyBytes, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(plaintext);
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
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(
                    Cipher.DECRYPT_MODE,
                    new SecretKeySpec(keyBytes, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(ciphertext);
        } catch (AEADBadTagException e) {
            throw new CryptoException("Could not decrypt payload", e);
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
