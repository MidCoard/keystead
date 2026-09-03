package top.focess.keystead.model;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

/**
 * Stored, non-secret routing identity for a vault.
 *
 * <p>A vault fingerprint is a truncated HMAC-SHA-256 over the vault's KDF salt, keyed by the
 * password-derived wrapping key (see {@code DefaultCryptoService#deriveFingerprint}). It replaces
 * the legacy vault id as the opaque routing token for server sync and is bound into record
 * additional-authenticated data.
 *
 * <p>Creation and stability: a newly created vault derives its initial fingerprint from its initial
 * passphrase and KDF salt. The result is then persisted as the vault's stable routing identity. Key
 * rotation, backup restore, provisioning, and adding or replacing local passphrase slots preserve
 * that stored value; they do not re-derive it from the currently installed passphrase slot.
 *
 * <p>Storage and disclosure: the fingerprint is a <em>non-secret</em> routing identity. It is stored
 * in the plaintext vault header so that passphrase-less device and recovery opens can recover it
 * (they have no wrapping key to derive it from), and it is disclosed to the sync server as a routing
 * token. It is integrity-protected on disk as part of the container AEAD's header AAD. Offline
 * passphrase protection rests on the Argon2id-gated wrapped vault key, not on
 * fingerprint secrecy: a holder of both the salt (from the file) and the fingerprint gains no
 * advantage over the offline-brute-force surface already presented by the wrapped vault key, since
 * each passphrase guess still pays the full password-KDF cost.
 *
 * @param value the {@link #BYTES}-byte fingerprint
 */
public record VaultFingerprint(byte @NonNull [] value) {

    /** Byte length of a vault fingerprint (64 bits). */
    public static final int BYTES = 8;

    /** Validates the record components. */
    public VaultFingerprint {
        Objects.requireNonNull(value, "value");
        if (value.length != BYTES) {
            throw new IllegalArgumentException(
                    "Vault fingerprint must be " + BYTES + " bytes, was " + value.length);
        }
        value = Arrays.copyOf(value, value.length);
    }

    /**
     * Returns a defensive copy of the fingerprint bytes.
     *
     * @return a defensive copy of the fingerprint bytes
     */
    @Override
    public byte @NonNull [] value() {
        return Arrays.copyOf(value, value.length);
    }

    /**
     * Returns the fingerprint as a lowercase hex string.
     *
     * @return the fingerprint as a lowercase hex string
     */
    public @NonNull String toHexString() {
        return HexFormat.of().formatHex(value);
    }

    /**
     * Parses a fingerprint from a hex string produced by {@link #toHexString}.
     *
     * <p>The hex string must decode to exactly {@link #BYTES} bytes; the constructor validates the
     * length. This is the inverse of {@link #toHexString} and is used to rebuild a fingerprint from a
     * stored hex form (for example a recovery or backup archive that carries the fingerprint as text).
     *
     * @param hex the hex string
     * @return the fingerprint
     * @throws IllegalArgumentException if the string is not valid hex or not {@link #BYTES} bytes
     */
    public static @NonNull VaultFingerprint fromHexString(@NonNull String hex) {
        Objects.requireNonNull(hex, "hex");
        return new VaultFingerprint(HexFormat.of().parseHex(hex));
    }

    @Override
    public @NonNull String toString() {
        return "VaultFingerprint[REDACTED " + value.length + " bytes]";
    }

    @Override
    public boolean equals(@NonNull Object object) {
        if (this == object) {
            return true;
        }
        if (!(object instanceof VaultFingerprint other)) {
            return false;
        }
        return Arrays.equals(value, other.value);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(value);
    }
}
