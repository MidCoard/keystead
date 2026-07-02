package top.focess.keystead.service;

import top.focess.keystead.model.VaultId;

public interface VaultService {

    VaultHandle createVault(CreateVaultRequest request, char[] masterPassword);

    VaultHandle openVault(VaultId vaultId, char[] masterPassword);
}
