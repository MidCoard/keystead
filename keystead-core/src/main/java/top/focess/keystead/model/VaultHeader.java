package top.focess.keystead.model;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.crypto.KdfParameters;

public final class VaultHeader {

    private final VaultId vaultId;
    private final int formatVersion;
    private final KdfParameters kdfParameters;
    private final KeyId vaultKeyId;
    private final byte[] wrappedVaultKey;
    private final Instant createdAt;
    private final Instant updatedAt;

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

    public @NonNull VaultId vaultId() {
        return vaultId;
    }

    public int formatVersion() {
        return formatVersion;
    }

    public @NonNull KdfParameters kdfParameters() {
        return kdfParameters;
    }

    public @NonNull String kdfAlgorithm() {
        return kdfParameters.algorithm();
    }

    public byte @NonNull [] kdfSalt() {
        return kdfParameters.salt();
    }

    public int kdfIterations() {
        return kdfParameters.required(KdfParameters.ITERATIONS);
    }

    public @NonNull KeyId vaultKeyId() {
        return vaultKeyId;
    }

    public byte @NonNull [] wrappedVaultKey() {
        return Arrays.copyOf(wrappedVaultKey, wrappedVaultKey.length);
    }

    public @NonNull Instant createdAt() {
        return createdAt;
    }

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
