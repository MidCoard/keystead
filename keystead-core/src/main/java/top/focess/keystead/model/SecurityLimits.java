package top.focess.keystead.model;

/** Resource ceilings applied at untrusted Core input boundaries. */
public final class SecurityLimits {

    /** Maximum byte size of a stored properties document. */
    public static final int MAX_STORED_PROPERTIES_BYTES = 1_048_576;

    /** Maximum byte size of an encrypted-envelope ciphertext. */
    public static final int MAX_ENVELOPE_CIPHERTEXT_BYTES = 1_048_576;

    /** Maximum byte size of an encrypted-envelope AAD. */
    public static final int MAX_ENVELOPE_AAD_BYTES = 65_536;

    /** Maximum character count of an encoded sync record. */
    public static final int MAX_ENCODED_SYNC_CHARACTERS = 2_097_152;

    /** Maximum byte size of a wrapped vault key package. */
    public static final int MAX_WRAPPED_KEY_PACKAGE_BYTES = 1_048_576;

    /** Maximum byte size of a KDF salt. */
    public static final int MAX_KDF_SALT_BYTES = 64;

    /** Maximum PBKDF2 iteration count. */
    public static final int MAX_PBKDF2_ITERATIONS = 10_000_000;

    /** Maximum number of named KDF parameter entries. */
    public static final int MAX_KDF_PARAMETER_ENTRIES = 16;

    /** Maximum character count of a KDF parameter name. */
    public static final int MAX_KDF_PARAMETER_NAME_CHARACTERS = 64;

    /** Byte size of an AES-256 key. */
    public static final int AES_256_KEY_BYTES = 32;

    private SecurityLimits() {}
}
