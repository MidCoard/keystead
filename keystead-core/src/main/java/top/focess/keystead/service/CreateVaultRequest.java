package top.focess.keystead.service;

import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.VaultId;

/**
 * Request to create a new password-protected vault.
 *
 * @param vaultId the id of the vault to create
 */
public record CreateVaultRequest(@NonNull VaultId vaultId) {

    public CreateVaultRequest {
        Objects.requireNonNull(vaultId, "vaultId");
    }
}
