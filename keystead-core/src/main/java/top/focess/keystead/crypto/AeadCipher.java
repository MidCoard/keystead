package top.focess.keystead.crypto;

import org.jspecify.annotations.NonNull;

/**
 * Pluggable authenticated-encryption-with-associated-data (AEAD) cipher used to encrypt secret
 * payloads and wrap vault keys.
 */
public interface AeadCipher {

    /** Returns the approved algorithm name.
     *
     * @return the algorithm name */
    @NonNull String algorithm();

    /** Returns the nonce size, in bytes, required by this cipher.
     *
     * @return the nonce size in bytes */
    int nonceSizeBytes();

    /**
     * Encrypts the plaintext with the given key, nonce, and additional authenticated data.
     *
     * @param keyBytes the secret key bytes
     * @param nonce the unique nonce
     * @param plaintext the plaintext to encrypt
     * @param aad the additional authenticated data
     * @return the ciphertext
     */
    byte @NonNull [] encrypt(
            byte @NonNull [] keyBytes,
            byte @NonNull [] nonce,
            byte @NonNull [] plaintext,
            byte @NonNull [] aad);

    /**
     * Decrypts the ciphertext with the given key, nonce, and additional authenticated data.
     *
     * @param keyBytes the secret key bytes
     * @param nonce the nonce used during encryption
     * @param ciphertext the ciphertext to decrypt
     * @param aad the additional authenticated data
     * @return the plaintext
     */
    byte @NonNull [] decrypt(
            byte @NonNull [] keyBytes,
            byte @NonNull [] nonce,
            byte @NonNull [] ciphertext,
            byte @NonNull [] aad);
}
