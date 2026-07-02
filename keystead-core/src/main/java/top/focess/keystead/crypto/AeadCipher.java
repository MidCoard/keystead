package top.focess.keystead.crypto;

import org.jspecify.annotations.NonNull;

public interface AeadCipher {

    @NonNull String algorithm();

    int nonceSizeBytes();

    byte @NonNull [] encrypt(
            byte @NonNull [] keyBytes,
            byte @NonNull [] nonce,
            byte @NonNull [] plaintext,
            byte @NonNull [] aad);

    byte @NonNull [] decrypt(
            byte @NonNull [] keyBytes,
            byte @NonNull [] nonce,
            byte @NonNull [] ciphertext,
            byte @NonNull [] aad);
}
