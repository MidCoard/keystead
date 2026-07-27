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

    /** Minimum Argon2id iteration count (time cost). */
    public static final int MIN_ARGON2ID_ITERATIONS = 1;

    /** Maximum Argon2id iteration count (time cost). */
    public static final int MAX_ARGON2ID_ITERATIONS = 100;

    /** Minimum Argon2id memory cost, in KiB. */
    public static final int MIN_ARGON2ID_MEMORY_KIB = 1_024;

    /** Maximum Argon2id memory cost, in KiB. */
    public static final int MAX_ARGON2ID_MEMORY_KIB = 1_048_576;

    /** Minimum Argon2id parallelism (lanes). */
    public static final int MIN_ARGON2ID_PARALLELISM = 1;

    /** Maximum Argon2id parallelism (lanes). */
    public static final int MAX_ARGON2ID_PARALLELISM = 64;

    /** Maximum number of named KDF parameter entries. */
    public static final int MAX_KDF_PARAMETER_ENTRIES = 16;

    /** Maximum character count of a KDF parameter name. */
    public static final int MAX_KDF_PARAMETER_NAME_CHARACTERS = 64;

    /** Byte size of an AES-256 key. */
    public static final int AES_256_KEY_BYTES = 32;

    /** Minimum character count of a single-secret share temp passphrase (bounds offline brute-force of a leaked share string). */
    public static final int SHARE_PASSPHRASE_MIN_CHARACTERS = 12;

    /** Minimum number of character classes (lower, upper, digit, symbol) in a share temp passphrase. */
    public static final int SHARE_PASSPHRASE_MIN_CHAR_CLASSES = 3;

    /** Minimum PBKDF2 iteration count accepted when minting a share. */
    public static final int SHARE_PBKDF2_MIN_ITERATIONS = 120_000;

    /** Maximum character count of a share title. */
    public static final int SHARE_MAX_TITLE_CHARACTERS = 256;

    /** Maximum character count of a sharer note in a share. */
    public static final int SHARE_MAX_NOTE_CHARACTERS = 4_096;

    /** Maximum number of fields in a share. */
    public static final int SHARE_MAX_FIELD_COUNT = 64;

    /** Maximum character count of a share field name. */
    public static final int SHARE_MAX_FIELD_NAME_CHARACTERS = 64;

    /** Maximum byte size of a share field value (fits a u16 length prefix). */
    public static final int SHARE_MAX_FIELD_VALUE_BYTES = 65_535;

    /** Maximum byte size of a decrypted share body. */
    public static final int SHARE_MAX_BODY_BYTES = 1_048_576;

    private SecurityLimits() {}
}
