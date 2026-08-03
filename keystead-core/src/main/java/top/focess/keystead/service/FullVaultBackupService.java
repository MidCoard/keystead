package top.focess.keystead.service;

import java.io.ByteArrayInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.crypto.KdfParameters;
import top.focess.keystead.crypto.VaultKey;
import top.focess.keystead.memory.Wipe;
import top.focess.keystead.memory.WipeableByteArrayOutputStream;
import top.focess.keystead.model.EncryptedEnvelope;
import top.focess.keystead.model.KeyId;
import top.focess.keystead.model.KeySlot;
import top.focess.keystead.model.SlotType;
import top.focess.keystead.model.VaultHeader;
import top.focess.keystead.store.OneFileVaultStore;
import top.focess.keystead.store.VaultFileFormat;
import top.focess.keystead.store.VaultStore;

/** Creates and restores independently password-protected complete vault backups. */
public final class FullVaultBackupService {

    private static final int PLAINTEXT_CHUNK_BYTES = 512 * 1_024;

    private final DefaultCryptoService crypto;
    private final Clock clock;

    /** Creates a service with default cryptography and clock. */
    public FullVaultBackupService() {
        this(new DefaultCryptoService(), Clock.systemUTC());
    }

    /**
     * Creates a service with supplied cryptography and clock.
     *
     * @param crypto cryptographic service used for wrapping and chunk encryption
     * @param clock clock used for archive and restored-header timestamps
     */
    public FullVaultBackupService(@NonNull DefaultCryptoService crypto, @NonNull Clock clock) {
        this.crypto = Objects.requireNonNull(crypto, "crypto");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Writes a complete `.ksbackup` archive for an open vault.
     *
     * @param vault open vault to back up
     * @param backupPassword caller-owned password protecting the archive
     * @param output destination for the encoded archive
     */
    public void export(
            @NonNull VaultHandle vault,
            char @NonNull [] backupPassword,
            @NonNull OutputStream output) {
        Objects.requireNonNull(vault, "vault");
        Objects.requireNonNull(backupPassword, "backupPassword");
        Objects.requireNonNull(output, "output");
        if (backupPassword.length == 0) {
            throw new IllegalArgumentException("Backup password must not be empty");
        }
        FullBackupArchiveCodec.write(vault.createFullBackup(backupPassword), output);
    }

    /**
     * Restores a complete backup to a new local vault protected by a new master passphrase.
     * Existing targets are rejected and never replaced.
     *
     * @param target new vault path; it must not already exist
     * @param input encoded `.ksbackup` source
     * @param backupPassword caller-owned password protecting the archive
     * @param newMasterPassphrase caller-owned passphrase for the restored local vault
     * @return an open handle for the restored vault
     */
    public @NonNull VaultHandle restore(
            @NonNull Path target,
            @NonNull InputStream input,
            char @NonNull [] backupPassword,
            char @NonNull [] newMasterPassphrase) {
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(input, "input");
        Objects.requireNonNull(backupPassword, "backupPassword");
        Objects.requireNonNull(newMasterPassphrase, "newMasterPassphrase");
        if (backupPassword.length == 0 || newMasterPassphrase.length == 0) {
            throw new IllegalArgumentException("Backup and new vault passwords must not be empty");
        }
        Path normalizedTarget = target.toAbsolutePath().normalize();
        if (Files.exists(normalizedTarget)) {
            throw new ValidationException("Backup restore target already exists");
        }
        FullBackupArchive archive = FullBackupArchiveCodec.read(input);
        byte @Nullable [] wrapped = null;
        @Nullable VaultKey vaultKey = null;
        byte @Nullable [] plaintext = null;
        try {
            wrapped = archive.wrappedVaultKey();
            vaultKey =
                    crypto.unwrapVaultKey(
                            archive.vaultKeyId(), wrapped, backupPassword, archive.backupKdf());
            plaintext = decryptPayload(archive, vaultKey);
            BackupReadResult read =
                    new VaultBackupService(clock).readFrom(new ByteArrayInputStream(plaintext));
            if (read.unsupported() != 0) {
                throw new ValidationException("Full backup contains unsupported entries");
            }
            BackupArchive inner = read.archive();
            if (!archive.fingerprint().equals(inner.vaultHeader().fingerprint())
                    || !archive.vaultKeyId().equals(inner.vaultHeader().vaultKeyId())) {
                throw new ValidationException("Full backup inner and outer vault bindings differ");
            }
            VaultHandle restored =
                    install(normalizedTarget, archive, inner, vaultKey, newMasterPassphrase);
            vaultKey = null;
            return restored;
        } finally {
            Wipe.wipe(wrapped);
            Wipe.wipe(plaintext);
            if (vaultKey != null) {
                vaultKey.close();
            }
        }
    }

    static @NonNull FullBackupArchive createArchive(
            @NonNull VaultStore store,
            @NonNull DefaultCryptoService crypto,
            @NonNull VaultKey vaultKey,
            char @NonNull [] backupPassword,
            @NonNull Clock clock) {
        Objects.requireNonNull(store, "store");
        Objects.requireNonNull(crypto, "crypto");
        Objects.requireNonNull(vaultKey, "vaultKey");
        Objects.requireNonNull(backupPassword, "backupPassword");
        Objects.requireNonNull(clock, "clock");
        if (backupPassword.length == 0) {
            throw new IllegalArgumentException("Backup password must not be empty");
        }
        byte @Nullable [] payload = null;
        byte @Nullable [] digest = null;
        byte @Nullable [] salt = null;
        byte @Nullable [] wrapped = null;
        try (WipeableByteArrayOutputStream output = new WipeableByteArrayOutputStream()) {
            VaultBackupService backup = new VaultBackupService(clock);
            BackupArchive inner = backup.export(store);
            backup.writeTo(inner, nonClosing(output));
            payload = output.toByteArray();
            digest = sha256(payload);
            salt = crypto.randomSalt();
            KdfParameters kdf = crypto.defaultArgon2idParameters(salt);
            wrapped = crypto.wrapVaultKey(vaultKey, backupPassword, kdf);
            Instant createdAt = clock.instant();
            int chunkCount =
                    Math.max(
                            1,
                            (payload.length + PLAINTEXT_CHUNK_BYTES - 1) / PLAINTEXT_CHUNK_BYTES);
            List<EncryptedEnvelope> chunks = new ArrayList<>(chunkCount);
            for (int index = 0; index < chunkCount; index++) {
                int start = index * PLAINTEXT_CHUNK_BYTES;
                int end = Math.min(payload.length, start + PLAINTEXT_CHUNK_BYTES);
                byte[] chunk = Arrays.copyOfRange(payload, start, end);
                byte[] aad =
                        FullBackupAad.encode(
                                FullBackupArchive.FORMAT_VERSION,
                                inner.vaultHeader().fingerprint(),
                                vaultKey.keyId(),
                                kdf,
                                wrapped,
                                digest,
                                createdAt,
                                index,
                                chunkCount);
                try {
                    chunks.add(crypto.encrypt(vaultKey, chunk, aad, createdAt));
                } finally {
                    Wipe.wipe(chunk);
                    Wipe.wipe(aad);
                }
            }
            return new FullBackupArchive(
                    FullBackupArchive.FORMAT_VERSION,
                    inner.vaultHeader().fingerprint(),
                    vaultKey.keyId(),
                    kdf,
                    wrapped,
                    digest,
                    chunks,
                    createdAt);
        } finally {
            Wipe.wipe(payload);
            Wipe.wipe(digest);
            Wipe.wipe(salt);
            Wipe.wipe(wrapped);
        }
    }

    private byte @NonNull [] decryptPayload(
            @NonNull FullBackupArchive archive, @NonNull VaultKey vaultKey) {
        try (WipeableByteArrayOutputStream output = new WipeableByteArrayOutputStream()) {
            byte[] wrapped = archive.wrappedVaultKey();
            byte[] digest = archive.payloadDigest();
            try {
                for (int index = 0; index < archive.chunks().size(); index++) {
                    byte[] aad =
                            FullBackupAad.encode(
                                    archive.formatVersion(),
                                    archive.fingerprint(),
                                    archive.vaultKeyId(),
                                    archive.backupKdf(),
                                    wrapped,
                                    digest,
                                    archive.createdAt(),
                                    index,
                                    archive.chunks().size());
                    byte[] chunk = null;
                    try {
                        chunk = crypto.decrypt(vaultKey, archive.chunks().get(index), aad);
                        output.write(chunk);
                    } finally {
                        Wipe.wipe(aad);
                        Wipe.wipe(chunk);
                    }
                }
                byte[] plaintext = output.toByteArray();
                byte[] actual = sha256(plaintext);
                try {
                    if (!MessageDigest.isEqual(digest, actual)) {
                        Wipe.wipe(plaintext);
                        throw new ValidationException("Full backup payload digest does not match");
                    }
                    return plaintext;
                } finally {
                    Wipe.wipe(actual);
                }
            } catch (java.io.IOException error) {
                throw new ValidationException("Could not assemble full backup payload", error);
            } finally {
                Wipe.wipe(wrapped);
                Wipe.wipe(digest);
            }
        }
    }

    private @NonNull VaultHandle install(
            @NonNull Path target,
            @NonNull FullBackupArchive archive,
            @NonNull BackupArchive inner,
            @NonNull VaultKey vaultKey,
            char @NonNull [] newMasterPassphrase) {
        Path parent = target.getParent();
        if (parent == null) {
            throw new ValidationException("Backup restore target has no parent directory");
        }
        try {
            Files.createDirectories(parent);
        } catch (java.io.IOException error) {
            throw new ValidationException("Could not create backup restore directory", error);
        }
        Path staging =
                parent.resolve(
                        "." + target.getFileName() + ".restore-" + UUID.randomUUID() + ".tmp");
        Path stagingLock = staging.resolveSibling(staging.getFileName() + ".lock");
        byte @Nullable [] salt = null;
        byte @Nullable [] wrapped = null;
        @Nullable OneFileVaultStore store = null;
        boolean installed = false;
        try {
            salt = crypto.randomSalt();
            KdfParameters localKdf = crypto.defaultArgon2idParameters(salt);
            wrapped = crypto.wrapVaultKey(vaultKey, newMasterPassphrase, localKdf);
            KeySlot passphraseSlot =
                    new KeySlot(SlotType.PASSPHRASE, new KeyId("passphrase"), localKdf, wrapped);
            VaultHeader restoredHeader =
                    new VaultHeader(
                            VaultFileFormat.FORMAT_VERSION,
                            archive.fingerprint(),
                            archive.vaultKeyId(),
                            List.of(passphraseSlot),
                            inner.vaultHeader().createdAt(),
                            clock.instant());
            store =
                    OneFileVaultStore.createWithVaultKey(
                            crypto, staging, vaultKey, restoredHeader, clock);
            vaultKey = null;
            new VaultBackupService(clock).restore(store, inner);
            store.close();
            store = null;
            moveWithoutReplacement(staging, target);
            installed = true;
            return new DefaultVaultService(crypto, clock).openVault(target, newMasterPassphrase);
        } finally {
            if (store != null) {
                store.close();
            }
            if (vaultKey != null) {
                vaultKey.close();
            }
            Wipe.wipe(salt);
            Wipe.wipe(wrapped);
            if (!installed) {
                deleteIfExists(staging);
            }
            deleteIfExists(stagingLock);
        }
    }

    private static void moveWithoutReplacement(@NonNull Path source, @NonNull Path target) {
        try {
            Files.move(source, target, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException error) {
            try {
                Files.move(source, target);
            } catch (java.io.IOException fallback) {
                throw new ValidationException("Could not install restored vault", fallback);
            }
        } catch (java.io.IOException error) {
            throw new ValidationException("Could not install restored vault", error);
        }
    }

    private static byte @NonNull [] sha256(byte @NonNull [] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA-256 is unavailable", error);
        }
    }

    private static @NonNull OutputStream nonClosing(@NonNull OutputStream output) {
        return new FilterOutputStream(output) {
            @Override
            public void close() throws IOException {
                flush();
            }
        };
    }

    private static void deleteIfExists(@NonNull Path path) {
        try {
            Files.deleteIfExists(path);
        } catch (java.io.IOException ignored) {
            // Best-effort cleanup of a non-installed staging artifact.
        }
    }
}
