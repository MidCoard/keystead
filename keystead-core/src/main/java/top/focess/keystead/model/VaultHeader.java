package top.focess.keystead.model;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.crypto.KdfParameters;

/**
 * Non-secret header for a vault: identifiers, KDF parameters, wrapped key, and timestamps. The
 * byte-array state is defensively copied on construction and on access.
 */
public final class VaultHeader {

    private final VaultId vaultId;
    private final int formatVersion;
    private final KdfParameters kdfParameters;
    private final KeyId vaultKeyId;
    private final byte[] wrappedVaultKey;
    private final Instant createdAt;
    private final Instant updatedAt;

    /**
     * Creates a header from explicit PBKDF2 parameters.
     *
     * @param vaultId the vault's stable identifier
     * @param formatVersion the vault format version; must be positive
     * @param kdfAlgorithm the key-derivation function algorithm name
     * @param kdfSalt the KDF salt
     * @param kdfIterations the KDF iteration count; must be positive
     * @param vaultKeyId the identifier of the vault key generation
     * @param wrappedVaultKey the vault key wrapped by the KDF-derived key
     * @param createdAt when the vault was created
     * @param updatedAt when the vault was last updated; must not be before {@code createdAt}
     */
    public VaultHeader(
            @NonNull VaultId vaultId,
            int formatVersion,
            @NonNull String kdfAlgorithm,
            byte @NonNull [] kdfSalt,
            int kdfIterations,
            @NonNull KeyId vaultKeyId,
            byte @NonNull [] wrappedVaultKey,
            @NonNull Instant createdAt,
            @NonNull Instant updatedAt) {
        this(
                vaultId,
                formatVersion,
                KdfParameters.pbkdf2(kdfAlgorithm, kdfSalt, kdfIterations),
                vaultKeyId,
                wrappedVaultKey,
                createdAt,
                updatedAt);
    }

    /**
     * Creates a header from structured KDF parameters.
     *
     * @param vaultId the vault's stable identifier
     * @param formatVersion the vault format version; must be positive
     * @param kdfParameters the key-derivation parameters
     * @param vaultKeyId the identifier of the vault key generation
     * @param wrappedVaultKey the vault key wrapped by the KDF-derived key
     * @param createdAt when the vault was created
     * @param updatedAt when the vault was last updated; must not be before {@code createdAt}
     */
    public VaultHeader(
            @NonNull VaultId vaultId,
            int formatVersion,
            @NonNull KdfParameters kdfParameters,
            @NonNull KeyId vaultKeyId,
            byte @NonNull [] wrappedVaultKey,
            @NonNull Instant createdAt,
            @NonNull Instant updatedAt) {
        this.vaultId = Objects.requireNonNull(vaultId, "vaultId");
        this.kdfParameters = Objects.requireNonNull(kdfParameters, "kdfParameters");
        this.vaultKeyId = Objects.requireNonNull(vaultKeyId, "vaultKeyId");
        Objects.requireNonNull(wrappedVaultKey, "wrappedVaultKey");
        this.createdAt = Objects.requireNonNull(createdAt, "createdAt");
        this.updatedAt = Objects.requireNonNull(updatedAt, "updatedAt");
        if (updatedAt.isBefore(createdAt)) {
            throw new IllegalArgumentException(
                    "Vault updated time must not be before created time");
        }
        if (formatVersion <= 0) {
            throw new IllegalArgumentException("Format version must be positive");
        }
        if (wrappedVaultKey.length > SecurityLimits.MAX_WRAPPED_KEY_PACKAGE_BYTES) {
            throw new IllegalArgumentException("Wrapped vault key exceeds the size limit");
        }
        this.formatVersion = formatVersion;
        this.wrappedVaultKey = Arrays.copyOf(wrappedVaultKey, wrappedVaultKey.length);
    }

    /**
     * Returns the vault's stable identifier.
     *
     * @return the vault's stable identifier
     */
    public @NonNull VaultId vaultId() {
        return vaultId;
    }

    /**
     * Returns the vault format version.
     *
     * @return the vault format version
     */
    public int formatVersion() {
        return formatVersion;
    }

    /**
     * Returns the structured key-derivation parameters.
     *
     * @return the key-derivation parameters
     */
    public @NonNull KdfParameters kdfParameters() {
        return kdfParameters;
    }

    /**
     * Returns the key-derivation function algorithm name.
     *
     * @return the key-derivation function algorithm name
     */
    public @NonNull String kdfAlgorithm() {
        return kdfParameters.algorithm();
    }

    /**
     * Returns a defensive copy of the KDF salt.
     *
     * @return a defensive copy of the KDF salt
     */
    public byte @NonNull [] kdfSalt() {
        return kdfParameters.salt();
    }

    /**
     * Returns the KDF iteration count.
     *
     * @return the KDF iteration count
     */
    public int kdfIterations() {
        return kdfParameters.required(KdfParameters.ITERATIONS);
    }

    /**
     * Returns the identifier of the vault key generation.
     *
     * @return the identifier of the vault key generation
     */
    public @NonNull KeyId vaultKeyId() {
        return vaultKeyId;
    }

    /**
     * Returns a defensive copy of the wrapped vault key.
     *
     * @return a defensive copy of the wrapped vault key
     */
    public byte @NonNull [] wrappedVaultKey() {
        return Arrays.copyOf(wrappedVaultKey, wrappedVaultKey.length);
    }

    /**
     * Returns when the vault was created.
     *
     * @return when the vault was created
     */
    public @NonNull Instant createdAt() {
        return createdAt;
    }

    /**
     * Returns when the vault was last updated.
     *
     * @return when the vault was last updated
     */
    public @NonNull Instant updatedAt() {
        return updatedAt;
    }

    @Override
    public @NonNull String toString() {
        return "VaultHeader[vaultId=%s, formatVersion=%d, kdfAlgorithm=%s, kdfSalt=[REDACTED %d bytes], kdfIterations=%d, vaultKeyId=%s, wrappedVaultKey=[REDACTED %d bytes], createdAt=%s, updatedAt=%s]"
                .formatted(
                        vaultId,
                        formatVersion,
                        kdfAlgorithm(),
                        kdfParameters.salt().length,
                        kdfIterations(),
                        vaultKeyId,
                        wrappedVaultKey.length,
                        createdAt,
                        updatedAt);
    }

    @Override
    public boolean equals(@NonNull Object object) {
        if (this == object) {
            return true;
        }
        if (!(object instanceof VaultHeader other)) {
            return false;
        }
        return formatVersion == other.formatVersion
                && vaultId.equals(other.vaultId)
                && kdfParameters.equals(other.kdfParameters)
                && vaultKeyId.equals(other.vaultKeyId)
                && Arrays.equals(wrappedVaultKey, other.wrappedVaultKey)
                && createdAt.equals(other.createdAt)
                && updatedAt.equals(other.updatedAt);
    }

    @Override
    public int hashCode() {
        int result =
                Objects.hash(
                        vaultId, formatVersion, kdfParameters, vaultKeyId, createdAt, updatedAt);
        return 31 * result + Arrays.hashCode(wrappedVaultKey);
    }
}
