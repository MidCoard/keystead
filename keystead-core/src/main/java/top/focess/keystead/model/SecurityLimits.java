package top.focess.keystead.model;

/** Resource ceilings applied at untrusted Core input boundaries. */
public final class SecurityLimits {

    public static final int MAX_STORED_PROPERTIES_BYTES = 1_048_576;
    public static final int MAX_ENVELOPE_CIPHERTEXT_BYTES = 1_048_576;
    public static final int MAX_ENVELOPE_AAD_BYTES = 65_536;
    public static final int MAX_ENCODED_SYNC_CHARACTERS = 2_097_152;
    public static final int MAX_WRAPPED_KEY_PACKAGE_BYTES = 1_048_576;
    public static final int MAX_KDF_SALT_BYTES = 64;
    public static final int MAX_PBKDF2_ITERATIONS = 10_000_000;
    public static final int MAX_KDF_PARAMETER_ENTRIES = 16;
    public static final int MAX_KDF_PARAMETER_NAME_CHARACTERS = 64;
    public static final int AES_256_KEY_BYTES = 32;

    private SecurityLimits() {}
}
