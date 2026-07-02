package top.focess.keystead.service;

import top.focess.keystead.model.VaultId;

import java.util.Objects;

public record CreateVaultRequest(VaultId vaultId) {

    public CreateVaultRequest {
        Objects.requireNonNull(vaultId, "vaultId");
    }
}
