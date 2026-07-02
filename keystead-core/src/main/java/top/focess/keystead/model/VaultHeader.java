package top.focess.keystead.model;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

public record VaultHeader(
    VaultId vaultId,
    int formatVersion,
    String kdfAlgorithm,
    byte[] kdfSalt,
    int kdfIterations,
    KeyId vaultKeyId,
    byte[] wrappedVaultKey,
    Instant createdAt,
    Instant updatedAt
) {

    public VaultHeader {
        Objects.requireNonNull(vaultId, "vaultId");
        Objects.requireNonNull(kdfAlgorithm, "kdfAlgorithm");
        Objects.requireNonNull(kdfSalt, "kdfSalt");
        Objects.requireNonNull(vaultKeyId, "vaultKeyId");
        Objects.requireNonNull(wrappedVaultKey, "wrappedVaultKey");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(updatedAt, "updatedAt");
        if (formatVersion <= 0) {
            throw new IllegalArgumentException("Format version must be positive");
        }
        if (kdfIterations <= 0) {
            throw new IllegalArgumentException("KDF iterations must be positive");
        }
        kdfSalt = Arrays.copyOf(kdfSalt, kdfSalt.length);
        wrappedVaultKey = Arrays.copyOf(wrappedVaultKey, wrappedVaultKey.length);
    }

    @Override
    public byte[] kdfSalt() {
        return Arrays.copyOf(kdfSalt, kdfSalt.length);
    }

    @Override
    public byte[] wrappedVaultKey() {
        return Arrays.copyOf(wrappedVaultKey, wrappedVaultKey.length);
    }

    @Override
    public String toString() {
        return "VaultHeader[vaultId=%s, formatVersion=%d, kdfAlgorithm=%s, kdfSalt=[REDACTED %d bytes], kdfIterations=%d, vaultKeyId=%s, wrappedVaultKey=[REDACTED %d bytes], createdAt=%s, updatedAt=%s]"
            .formatted(vaultId, formatVersion, kdfAlgorithm, kdfSalt.length, kdfIterations, vaultKeyId, wrappedVaultKey.length, createdAt, updatedAt);
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (!(object instanceof VaultHeader other)) {
            return false;
        }
        return formatVersion == other.formatVersion
            && kdfIterations == other.kdfIterations
            && vaultId.equals(other.vaultId)
            && kdfAlgorithm.equals(other.kdfAlgorithm)
            && Arrays.equals(kdfSalt, other.kdfSalt)
            && vaultKeyId.equals(other.vaultKeyId)
            && Arrays.equals(wrappedVaultKey, other.wrappedVaultKey)
            && createdAt.equals(other.createdAt)
            && updatedAt.equals(other.updatedAt);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(vaultId, formatVersion, kdfAlgorithm, kdfIterations, vaultKeyId, createdAt, updatedAt);
        result = 31 * result + Arrays.hashCode(kdfSalt);
        result = 31 * result + Arrays.hashCode(wrappedVaultKey);
        return result;
    }
}
