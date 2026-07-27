package top.focess.keystead.share;

import top.focess.keystead.crypto.CryptoAlgorithmRegistry;

/**
 * Binary-format constants for the single-secret share envelope (Landing 3).
 *
 * <p>A share is a self-contained encrypted string
 * {@code keystead-share:v1:<base64url>}. The plaintext header (magic, version, KDF
 * parameters and nonce) doubles as the AEAD additional-authenticated-data, so any
 * tampering with routing/versioning parameters is detected at decryption time. The
 * body that the AEAD ciphertext decrypts to carries the secret payload.
 *
 * <p>This type is package-private: callers interact with {@link ShareService}.
 */
final class ShareFormat {

    /** Magic bytes that prefix every share byte stream ({@code "KSTS"}). */
    static final byte[] MAGIC = new byte[] {'K', 'S', 'T', 'S'};

    /** Share format version. Currently fixed at {@code 1}. */
    static final int VERSION = 1;

    /** Body (decrypted payload) version. Currently fixed at {@code 1}. */
    static final int BODY_VERSION = 1;

    /** Envelope (ciphertext + algorithm) version. Currently fixed at {@code 1}. */
    static final int ENVELOPE_VERSION = 1;

    /** Human-readable prefix on every share string. */
    static final String PREFIX = "keystead-share:v1:";

    /** KDF algorithm used to turn the temp passphrase into the AEAD key. */
    static final String KDF_ALGORITHM = CryptoAlgorithmRegistry.KDF_PBKDF2_HMAC_SHA256;

    /** AEAD algorithm protecting the share body. */
    static final String AEAD_ALGORITHM = CryptoAlgorithmRegistry.AEAD_AES_256_GCM;

    private ShareFormat() {
        throw new AssertionError("No instances");
    }
}
