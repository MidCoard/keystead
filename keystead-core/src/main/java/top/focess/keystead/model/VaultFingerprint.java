package top.focess.keystead.model;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

/**
 * Non-stored, passphrase-derived routing identifier for a vault.
 *
 * <p>A vault fingerprint is computed at unlock as a truncated HMAC-SHA-256 over the vault's KDF
 * salt, keyed by the password-derived wrapping key (see {@code DefaultCryptoService#deriveFingerprint}).
 * It is <em>not</em> stored in the vault file: it replaces the legacy vault id as the opaque routing
 * token for server sync and is bound into record additional-authenticated data.
 *
 * <p>Stability: two vaults with different KDF salts yield different fingerprints. The fingerprint is
 * stable across vault-key rotations, because the wrapping key is derived from the passphrase and salt
 * alone and is unchanged when only the data-encryption key is rewrapped. It changes only when the
 * passphrase or salt changes.
 *
 * <p>Disclosure model: the fingerprint is secret-derived but is intentionally disclosed to the sync
 * server as a routing token. It cannot be used to recover the passphrase offline, because the server
 * never receives the KDF salt (the vault file is never uploaded), so it cannot recompute the password
 * KDF. A holder of both the salt (from a copied file) and the fingerprint gains no advantage over the
 * existing offline-brute-force surface already presented by the wrapped vault key: both are gated by
 * the password KDF iteration count.
 *
 * @param value the {@link #BYTES}-byte fingerprint
 */
public record VaultFingerprint(byte @NonNull [] value) {

    /** Byte length of a vault fingerprint (128 bits). */
    public static final int BYTES = 16;

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
