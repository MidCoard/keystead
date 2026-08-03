package top.focess.keystead.service;

import java.nio.file.Path;
import org.jspecify.annotations.NonNull;

/**
 * Entry point for creating, opening, provisioning, and rotating v2 single-file vaults.
 *
 * <p>A vault is one opaque file persisted by a {@link top.focess.keystead.store.OneFileVaultStore}.
 * The service derives and wraps a random data-encryption key (DEK) from a passphrase under an
 * Argon2id passphrase slot, or unwraps one from a device-wrapped package, and returns a live {@link
 * VaultHandle} that holds the unlocked key only for the lifetime of the handle. Closing the handle
 * destroys its key material and releases the file locks.
 *
 * <p>A vault is identified locally by its file path and, for routing, by its {@link
 * top.focess.keystead.model.VaultFingerprint}; there is no vault id. New vaults derive the
 * fingerprint from their initial passphrase. Server-provisioned copies import that routing
 * fingerprint and preserve it when installing a different device-local passphrase slot.
 *
 * <p>The caller owns every {@code char[]} and {@code byte[]} passed to this service. Passphrases,
 * device private keys, and context buffers must be wiped by the caller once the call returns; the
 * service copies what it needs and wipes its own transient copies, but it cannot reach arrays it
 * does not own.
 */
public interface VaultService {

    /**
     * Creates a new passphrase-protected vault file and returns a handle holding its unlocked key.
     *
     * <p>The {@code passphrase} derives an Argon2id wrapping key from a fresh salt; the derived key
     * wraps a freshly generated random DEK and is not used directly as the record-encryption key. The
     * passphrase-derived fingerprint, the DEK id, and the passphrase key slot are persisted in the
     * plaintext header before the handle is returned.
     *
     * @param request the vault file path and creation parameters
     * @param passphrase caller-owned passphrase; wiped by the caller, not by this service
     * @return a live handle owning the new vault key
     * @throws ValidationException if the vault file already exists or the request is invalid
     */
    @NonNull VaultHandle createVault(
            @NonNull CreateVaultRequest request, char @NonNull [] passphrase);

    /**
     * Opens an existing passphrase-protected vault file and returns a handle holding its unlocked key.
     *
     * @param file the vault file to open
     * @param passphrase caller-owned passphrase; wiped by the caller
     * @return a live handle owning the unwrapped vault key
     * @throws ValidationException if the vault file does not exist or has no passphrase key slot
     * @throws top.focess.keystead.crypto.CryptoException if the passphrase is wrong or the file is
     *     corrupt
     */
    @NonNull VaultHandle openVault(@NonNull Path file, char @NonNull [] passphrase);

    /**
     * Rotates the data-encryption key and re-encrypts every current record under the new key.
     *
     * <p>The new DEK is wrapped under the same passphrase and the same Argon2id parameters (so the
     * fingerprint is unchanged), and the new header, re-encrypted records, and preserved tombstones
     * are committed as one atomic store mutation. Device slots are dropped: a passphrase rotation
     * can only re-wrap the passphrase slot. On failure the previous key and records are left untouched.
     *
     * @param file the vault file whose key should be rotated
     * @param passphrase caller-owned passphrase; wiped by the caller
     * @return a live handle owning the new vault key
     * @throws ValidationException if the vault file does not exist or has no passphrase slot
     * @throws top.focess.keystead.crypto.CryptoException if the passphrase is wrong
     */
    @NonNull VaultHandle rotateVaultKey(@NonNull Path file, char @NonNull [] passphrase);

    /**
     * Provisions a new vault file on this device from a device-wrapped vault-key package.
     *
     * <p>Used when a vault's DEK was wrapped for this device's public key on another device. The
     * package's fingerprint is written into the provisioned header; no passphrase is involved. The
     * provisioned vault starts empty and is filled by syncing records from the server (the records
     * are encrypted under the same shared DEK and bound to the same fingerprint).
     *
     * @param file the vault file to create; must not already exist as a vault
     * @param keyPackage the device-wrapped vault key package produced by {@link
     *     VaultHandle#wrapVaultKeyPackageForDevice}
     * @param devicePrivateKey caller-owned device private key; wiped by the caller
     * @param context caller-owned binding context used when the key was wrapped; wiped by the caller
     * @return a live handle owning the unwrapped vault key
     * @throws ValidationException if the package cannot be unwrapped for this device
     */
    @NonNull VaultHandle provisionVault(
            @NonNull Path file,
            @NonNull DeviceVaultKeyPackage keyPackage,
            byte @NonNull [] devicePrivateKey,
            byte @NonNull [] context);

    /**
     * Opens a device-provisioned vault file with its device private key, without a passphrase.
     *
     * <p>The header's {@link top.focess.keystead.model.SlotType#DEVICE DEVICE} slots are tried in
     * order until one unwraps under the supplied private key and binding context.
     *
     * @param file the vault file to open
     * @param devicePrivateKey caller-owned device private key; wiped by the caller
     * @param context caller-owned binding context used when the key was wrapped; wiped by the caller
     * @return a live handle owning the unwrapped vault key
     * @throws ValidationException if the vault file does not exist or no device slot unwraps for this
     *     device key
     */
    @NonNull VaultHandle openVaultWithDeviceKey(
            @NonNull Path file, byte @NonNull [] devicePrivateKey, byte @NonNull [] context);
}
