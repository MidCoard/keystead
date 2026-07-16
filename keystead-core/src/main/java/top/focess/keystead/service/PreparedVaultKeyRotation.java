package top.focess.keystead.service;

import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.KeyId;
import top.focess.keystead.model.VaultId;

/**
 * A target vault key and its re-encrypted records before the local journal is committed.
 *
 * <p>Returned by {@link VaultHandle#prepareVaultKeyRotation} or {@link
 * VaultHandle#resumeVaultKeyRotation}. The next key and re-encrypted records are held in memory and
 * the live vault is unchanged until {@link #commitWithDevicePackage} commits the rotation as one
 * atomic store mutation. Closing an uncommitted rotation discards the target key and re-enables
 * mutations on the source handle.
 */
public interface PreparedVaultKeyRotation extends AutoCloseable {

    /** @return the vault this rotation targets. */
    @NonNull VaultId vaultId();

    /** @return the id of the key currently protecting the vault. */
    @NonNull KeyId sourceVaultKeyId();

    /** @return the id of the key that will protect the vault after commit. */
    @NonNull KeyId targetVaultKeyId();

    /**
     * Wraps the target key for another device's public key. Each package produced here is recorded
     * so the local commit can be authorized.
     *
     * @param publicKey the recipient device's public key
     * @param context caller-owned binding context; wiped by the caller
     * @return the device-wrapped target key package
     */
    @NonNull DeviceVaultKeyPackage wrapVaultKeyPackageForDevice(
            byte @NonNull [] publicKey, byte @NonNull [] context);

    /**
     * Commits the rotation using a local device package that this rotation produced, returning a
     * new handle owning the target key. The source handle is closed.
     *
     * @param localPackage a package previously produced by this rotation for the local device
     * @return a live handle owning the target vault key
     * @throws ValidationException if the package was not produced by this rotation
     */
    @NonNull VaultHandle commitWithDevicePackage(@NonNull DeviceVaultKeyPackage localPackage);

    /** @return whether the rotation has been committed. */
    boolean isCommitted();

    /**
     * Discards the target key and re-encrypted records if the rotation has not been committed; a
     * no-op once committed.
     */
    @Override
    void close();
}
