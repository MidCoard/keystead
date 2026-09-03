package top.focess.keystead.service;

import java.nio.file.Path;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

/**
 * Request to create a new password-protected vault at a given file path. A vault is identified
 * locally by its file path; no vault id is supplied.
 *
 * @param file the path of the vault file to create
 */
public record CreateVaultRequest(@NonNull Path file) {

    /** Validates the record components. */
    public CreateVaultRequest {
        Objects.requireNonNull(file, "file");
    }
}
