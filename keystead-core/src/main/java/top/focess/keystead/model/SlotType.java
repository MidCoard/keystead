package top.focess.keystead.model;

import org.jspecify.annotations.NonNull;

/**
 * A key-slot type: how the data-encryption key is wrapped for a given recipient credential in a
 * multi-slot vault header.
 *
 * <ul>
 *   <li>{@link #PASSPHRASE}: the DEK is wrapped under an Argon2id passphrase-derived key; the slot
 *       carries its own KDF parameters.
 *   <li>{@link #DEVICE}: the DEK is wrapped to a device public key via hybrid encryption.
 * </ul>
 *
 * <p>Any single slot unlocks the vault. The on-disk byte code is stable across versions.
 */
public enum SlotType {
    /** DEK wrapped under an Argon2id passphrase-derived key. Carries KDF parameters. */
    PASSPHRASE(1),
    /** DEK wrapped to a device public key via hybrid encryption. */
    DEVICE(2);

    private final byte code;

    SlotType(int code) {
        this.code = (byte) code;
    }

    /** Returns the on-disk byte code for this slot type.
     *
     * @return the byte code */
    public byte code() {
        return code;
    }

    /** Returns the slot type for the given on-disk byte code.
     *
     * @param code the byte code
     * @return the slot type
     * @throws IllegalArgumentException if the code is not a recognized slot type */
    public static @NonNull SlotType fromCode(int code) {
        for (SlotType type : values()) {
            if (type.code == (byte) code) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown key slot type: " + code);
    }
}
