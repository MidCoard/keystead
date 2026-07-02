package top.focess.keystead.service;

import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.VaultId;

public interface VaultService {

    @NonNull VaultHandle createVault(
            @NonNull CreateVaultRequest request, char @NonNull [] masterPassword);

    @NonNull VaultHandle openVault(@NonNull VaultId vaultId, char @NonNull [] masterPassword);
}
