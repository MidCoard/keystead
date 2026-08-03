package top.focess.keystead.service;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.crypto.KdfParameters;
import top.focess.keystead.model.EncryptedEnvelope;
import top.focess.keystead.model.KeyId;
import top.focess.keystead.model.VaultFingerprint;

/**
 * Password-wrapped vault key plus authenticated encrypted chunks of a complete backup archive.
 *
 * @param formatVersion outer archive format version
 * @param fingerprint vault routing fingerprint bound into every chunk
 * @param vaultKeyId identifier of the wrapped vault key
 * @param backupKdf parameters used to derive the backup wrapping key
 * @param wrappedVaultKey vault key wrapped by the backup password
 * @param payloadDigest SHA-256 digest of the decrypted inner archive
 * @param chunks authenticated encrypted chunks of the inner archive
 * @param createdAt archive creation time
 */
public record FullBackupArchive(
        int formatVersion,
        @NonNull VaultFingerprint fingerprint,
        @NonNull KeyId vaultKeyId,
        @NonNull KdfParameters backupKdf,
        byte @NonNull [] wrappedVaultKey,
        byte @NonNull [] payloadDigest,
        @NonNull List<EncryptedEnvelope> chunks,
        @NonNull Instant createdAt) {

    /** Current `.ksbackup` outer format version. */
    public static final int FORMAT_VERSION = 1;

    /** Validates and defensively copies archive components. */
    public FullBackupArchive {
        if (formatVersion != FORMAT_VERSION) {
            throw new ValidationException("Full backup format version is unsupported");
        }
        Objects.requireNonNull(fingerprint, "fingerprint");
        Objects.requireNonNull(vaultKeyId, "vaultKeyId");
        Objects.requireNonNull(backupKdf, "backupKdf");
        Objects.requireNonNull(wrappedVaultKey, "wrappedVaultKey");
        Objects.requireNonNull(payloadDigest, "payloadDigest");
        Objects.requireNonNull(chunks, "chunks");
        Objects.requireNonNull(createdAt, "createdAt");
        if (wrappedVaultKey.length == 0 || wrappedVaultKey.length > 1_048_576) {
            throw new ValidationException("Full backup wrapped vault key is invalid");
        }
        if (payloadDigest.length != 32) {
            throw new ValidationException("Full backup payload digest is invalid");
        }
        if (chunks.isEmpty() || chunks.size() > 64) {
            throw new ValidationException("Full backup chunk count is invalid");
        }
        wrappedVaultKey = Arrays.copyOf(wrappedVaultKey, wrappedVaultKey.length);
        payloadDigest = Arrays.copyOf(payloadDigest, payloadDigest.length);
        chunks = List.copyOf(chunks);
    }

    /** Returns a defensive copy of the password-wrapped vault key. */
    @Override
    public byte @NonNull [] wrappedVaultKey() {
        return Arrays.copyOf(wrappedVaultKey, wrappedVaultKey.length);
    }

    /** Returns a defensive copy of the inner archive digest. */
    @Override
    public byte @NonNull [] payloadDigest() {
        return Arrays.copyOf(payloadDigest, payloadDigest.length);
    }

    @Override
    public @NonNull String toString() {
        return "FullBackupArchive[formatVersion=%d, fingerprint=%s, vaultKeyId=%s, backupKdf=%s, wrappedVaultKey=[REDACTED %d bytes], payloadDigest=[REDACTED], chunks=%d, createdAt=%s]"
                .formatted(
                        formatVersion,
                        fingerprint,
                        vaultKeyId,
                        backupKdf,
                        wrappedVaultKey.length,
                        chunks.size(),
                        createdAt);
    }
}
