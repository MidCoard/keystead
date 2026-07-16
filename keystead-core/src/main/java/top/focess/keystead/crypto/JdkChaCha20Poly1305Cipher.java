package top.focess.keystead.crypto;

import java.security.GeneralSecurityException;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.jspecify.annotations.NonNull;

/**
 * JDK-backed ChaCha20-Poly1305 {@link AeadCipher} using a 256-bit key and a 96-bit nonce. Nonces
 * are caller-supplied; the caller is responsible for uniqueness.
 */
public final class JdkChaCha20Poly1305Cipher implements AeadCipher {

    /** Creates a JDK-backed ChaCha20-Poly1305 cipher. */
    public JdkChaCha20Poly1305Cipher() {}

    private static final String JCA_ALGORITHM = "ChaCha20-Poly1305";
    private static final String KEY_ALGORITHM = "ChaCha20";
    private static final int KEY_SIZE_BYTES = 32;
    private static final int NONCE_SIZE_BYTES = 12;

    @Override
    public @NonNull String algorithm() {
        return CryptoAlgorithmRegistry.AEAD_CHACHA20_POLY1305;
    }

    @Override
    public int nonceSizeBytes() {
        return NONCE_SIZE_BYTES;
    }

    @Override
    public byte @NonNull [] encrypt(
            byte @NonNull [] keyBytes,
            byte @NonNull [] nonce,
            byte @NonNull [] plaintext,
            byte @NonNull [] aad) {
        return run(Cipher.ENCRYPT_MODE, keyBytes, nonce, plaintext, aad, "encrypt");
    }

    @Override
    public byte @NonNull [] decrypt(
            byte @NonNull [] keyBytes,
            byte @NonNull [] nonce,
            byte @NonNull [] ciphertext,
            byte @NonNull [] aad) {
        return run(Cipher.DECRYPT_MODE, keyBytes, nonce, ciphertext, aad, "decrypt");
    }

    private byte @NonNull [] run(
            int mode,
            byte @NonNull [] keyBytes,
            byte @NonNull [] nonce,
            byte @NonNull [] input,
            byte @NonNull [] aad,
            @NonNull String operation) {
        Objects.requireNonNull(keyBytes, "keyBytes");
        Objects.requireNonNull(nonce, "nonce");
        Objects.requireNonNull(input, "input");
        Objects.requireNonNull(aad, "aad");
        if (keyBytes.length != KEY_SIZE_BYTES) {
            throw new CryptoException("ChaCha20-Poly1305 requires a 256-bit key");
        }
        if (nonce.length != NONCE_SIZE_BYTES) {
            throw new CryptoException("ChaCha20-Poly1305 requires a 96-bit nonce");
        }
        try {
            Cipher cipher = Cipher.getInstance(JCA_ALGORITHM);
            SecretKeySpec key = new SecretKeySpec(keyBytes, KEY_ALGORITHM);
            cipher.init(mode, key, new IvParameterSpec(nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(input);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Could not " + operation + " ChaCha20-Poly1305 payload", e);
        }
    }
}
