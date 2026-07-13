package top.focess.keystead.service;

import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.KeyId;
import top.focess.keystead.model.VaultId;

/** A target vault key and its re-encrypted records before the local journal is committed. */
public interface PreparedVaultKeyRotation extends AutoCloseable {

    @NonNull VaultId vaultId();

    @NonNull KeyId sourceVaultKeyId();

    @NonNull KeyId targetVaultKeyId();

    @NonNull DeviceVaultKeyPackage wrapVaultKeyPackageForDevice(
            byte @NonNull [] publicKey, byte @NonNull [] context);

    @NonNull VaultHandle commitWithDevicePackage(@NonNull DeviceVaultKeyPackage localPackage);

    boolean isCommitted();

    @Override
    void close();
}
