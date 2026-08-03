package top.focess.keystead.model;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

/**
 * Plaintext v2 vault header: format version, routing fingerprint, vault key id, the
 * multi-slot key list, and timestamps.
 *
 * <p>A v2 vault carries no stored vault identifier; identity is the file path locally and the
 * {@link VaultFingerprint} for routing and AAD binding. A newly created vault derives that
 * fingerprint from its initial passphrase; a server-provisioned copy imports and preserves it.
 * The same
 * data-encryption key is wrapped under one or more {@link KeySlot slots}; any single slot unlocks
 * the vault. The fingerprint is stable across data-encryption-key rotations and when a
 * server-provisioned copy installs a device-local passphrase slot.
 */
public record VaultHeader(
        int formatVersion,
        @NonNull VaultFingerprint fingerprint,
        @NonNull KeyId vaultKeyId,
        @NonNull List<@NonNull KeySlot> slots,
        @NonNull Instant createdAt,
        @NonNull Instant updatedAt) {

    /** Maximum number of key slots in a single vault header. */
    public static final int MAX_SLOTS = 64;

    /** Validates the record components. */
    public VaultHeader {
        Objects.requireNonNull(fingerprint, "fingerprint");
        Objects.requireNonNull(vaultKeyId, "vaultKeyId");
        Objects.requireNonNull(slots, "slots");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(updatedAt, "updatedAt");
        if (formatVersion <= 0) {
            throw new IllegalArgumentException("Format version must be positive");
        }
        if (slots.isEmpty()) {
            throw new IllegalArgumentException("A vault header must have at least one key slot");
        }
        if (slots.size() > MAX_SLOTS) {
            throw new IllegalArgumentException("A vault header has too many key slots");
        }
        if (updatedAt.isBefore(createdAt)) {
            throw new IllegalArgumentException(
                    "Vault updated time must not be before created time");
        }
        slots = List.copyOf(slots);
    }

    /** Returns a defensive copy of the key slots.
     *
     * @return a defensive copy of the key slots */
    @Override
    public @NonNull List<@NonNull KeySlot> slots() {
        return List.copyOf(slots);
    }

    /** Returns a copy of this header with the updated-at timestamp replaced.
     *
     * @param updatedAt the new updated-at timestamp; must not be before {@code createdAt}
     * @return a copy of this header with the updated-at timestamp replaced */
    public @NonNull VaultHeader withUpdatedAt(@NonNull Instant updatedAt) {
        return new VaultHeader(formatVersion, fingerprint, vaultKeyId, slots, createdAt, updatedAt);
    }

    /** Returns a copy of this header with the vault key id and slots replaced, for a key rotation.
     *
     * @param vaultKeyId the new vault key id
     * @param slots the new key slots
     * @param updatedAt the new updated-at timestamp
     * @return a copy of this header with the vault key id and slots replaced */
    public @NonNull VaultHeader withVaultKey(
            @NonNull KeyId vaultKeyId,
            @NonNull List<@NonNull KeySlot> slots,
            @NonNull Instant updatedAt) {
        return new VaultHeader(formatVersion, fingerprint, vaultKeyId, slots, createdAt, updatedAt);
    }

    /** Returns the first passphrase slot, or empty if the header has none.
     *
     * @return the first passphrase slot, or empty if the header has none */
    public java.util.@NonNull Optional<KeySlot> firstPassphraseSlot() {
        for (KeySlot slot : slots) {
            if (slot.slotType() == SlotType.PASSPHRASE) {
                return java.util.Optional.of(slot);
            }
        }
        return java.util.Optional.empty();
    }

    @Override
    public @NonNull String toString() {
        return "VaultHeader[formatVersion=%d, fingerprint=%s, vaultKeyId=%s, slots=%d, createdAt=%s, updatedAt=%s]"
                .formatted(
                        formatVersion, fingerprint, vaultKeyId, slots.size(), createdAt, updatedAt);
    }
}
