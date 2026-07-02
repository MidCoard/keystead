package top.focess.keystead.service;

import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.VaultId;

public record CreateVaultRequest(@NonNull VaultId vaultId) {

    public CreateVaultRequest {
        Objects.requireNonNull(vaultId, "vaultId");
    }
}
