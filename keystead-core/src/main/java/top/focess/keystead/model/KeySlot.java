package top.focess.keystead.model;

import java.util.Arrays;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.crypto.KdfParameters;

/**
 * One key slot in a v2 multi-slot vault header: a single credential that can unwrap the
 * data-encryption key.
 *
 * @param slotType how the DEK is wrapped (passphrase / device / recovery)
 * @param slotKeyId the slot's recipient identifier ("passphrase", a device id, or an enrollment id)
 * @param kdfParameters the password KDF parameters; required for {@link SlotType#PASSPHRASE}, null
 *     for {@link SlotType#DEVICE} and {@link SlotType#RECOVERY}
 * @param wrappedVaultKey the slot-specific wrapping of the DEK bytes
 */
public record KeySlot(
        @NonNull SlotType slotType,
        @NonNull KeyId slotKeyId,
        @Nullable KdfParameters kdfParameters,
        byte @NonNull [] wrappedVaultKey) {

    /** Validates the record components. */
    public KeySlot {
        Objects.requireNonNull(slotType, "slotType");
        Objects.requireNonNull(slotKeyId, "slotKeyId");
        Objects.requireNonNull(wrappedVaultKey, "wrappedVaultKey");
        if (slotType == SlotType.PASSPHRASE) {
            Objects.requireNonNull(kdfParameters, "kdfParameters");
        } else if (kdfParameters != null) {
            throw new IllegalArgumentException(
                    "KDF parameters are only permitted on passphrase slots");
        }
        if (wrappedVaultKey.length > SecurityLimits.MAX_WRAPPED_KEY_PACKAGE_BYTES) {
            throw new IllegalArgumentException("Wrapped vault key exceeds the size limit");
        }
        wrappedVaultKey = Arrays.copyOf(wrappedVaultKey, wrappedVaultKey.length);
    }

    /** Returns a defensive copy of the wrapped vault key.
     *
     * @return a defensive copy of the wrapped vault key */
    @Override
    public byte @NonNull [] wrappedVaultKey() {
        return Arrays.copyOf(wrappedVaultKey, wrappedVaultKey.length);
    }

    /** Returns the KDF parameters, or null for non-passphrase slots.
     *
     * @return the KDF parameters, or null for non-passphrase slots */
    @Override
    public @Nullable KdfParameters kdfParameters() {
        return kdfParameters;
    }

    @Override
    public @NonNull String toString() {
        return "KeySlot[slotType=%s, slotKeyId=%s, kdfParameters=%s, wrappedVaultKey=[REDACTED %d bytes]]"
                .formatted(slotType, slotKeyId, kdfParameters, wrappedVaultKey.length);
    }

    @Override
    public boolean equals(@NonNull Object object) {
        if (this == object) {
            return true;
        }
        if (!(object instanceof KeySlot other)) {
            return false;
        }
        return slotType.equals(other.slotType)
                && slotKeyId.equals(other.slotKeyId)
                && Objects.equals(kdfParameters, other.kdfParameters)
                && Arrays.equals(wrappedVaultKey, other.wrappedVaultKey);
    }

    @Override
    public int hashCode() {
        return 31 * Objects.hash(slotType, slotKeyId, kdfParameters)
                + Arrays.hashCode(wrappedVaultKey);
    }
}
