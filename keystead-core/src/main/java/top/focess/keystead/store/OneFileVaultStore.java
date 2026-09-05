package top.focess.keystead.store;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.crypto.KdfParameters;
import top.focess.keystead.crypto.VaultKey;
import top.focess.keystead.model.DeletedSecretRecord;
import top.focess.keystead.model.EncryptedSecretRecord;
import top.focess.keystead.model.KeyId;
import top.focess.keystead.model.KeySlot;
import top.focess.keystead.model.SecretId;
import top.focess.keystead.model.SecretMetadata;
import top.focess.keystead.model.SlotType;
import top.focess.keystead.model.VaultFingerprint;
import top.focess.keystead.model.VaultHeader;

/**
 * Single-file {@link VaultStore} for the current vault format.
 *
 * <p>An {@code OneFileVaultStore} is bound to exactly one vault file. It holds the unlocked vault
 * key (data-encryption key), the vault header, and the decrypted record set in memory, and rewrites
 * the whole container atomically on every mutation: the header and records are re-serialized, the
 * body is encrypted under the vault key with the header as additional-authenticated data, and the
 * file is replaced via a temp-file, fsync, atomic-rename sequence. There is no vault id; identity is
 * the file path locally and the {@link VaultFingerprint} for routing.
 *
 * <p>Concurrency: a process-wide lock map prevents two stores for the same canonical path in one
 * JVM, and an exclusive {@link FileLock} on a sibling {@code .lock} file prevents concurrent
 * processes. Every mutating method is {@code synchronized} so a single store is safe for concurrent
 * threads. The store owns the vault key and the locks; {@link #close()} destroys the key material
 * and releases them.
 *
 * <p>Lifecycles are started by the {@link #create}, {@link #open}, and {@link #openWithVaultKey}
 * factories, which acquire the locks before touching the file so creation and recovery never race
 * with another writer.
 */
public final class OneFileVaultStore implements VaultStore, AutoCloseable {

    private static final ConcurrentMap<Path, Object> PROCESS_LOCKS = new ConcurrentHashMap<>();

    private final Path file;
    private final DefaultCryptoService crypto;
    private final Clock clock;
    private final LockHandle lockHandle;

    private VaultKey vaultKey;
    private VaultHeader header;
    private long vaultRevision;
    private final Map<SecretId, EncryptedSecretRecord> active = new LinkedHashMap<>();
    private final Map<SecretId, DeletedSecretRecord> deleted = new LinkedHashMap<>();
    private boolean closed;
    private boolean mutationInProgress;
    private boolean persistenceRequested;

    private OneFileVaultStore(
            @NonNull Path file,
            @NonNull DefaultCryptoService crypto,
            @NonNull Clock clock,
            @NonNull VaultKey vaultKey,
            @NonNull VaultHeader header,
            long vaultRevision,
            @NonNull LockHandle lockHandle) {
        this.file = file;
        this.crypto = crypto;
        this.clock = clock;
        this.vaultKey = vaultKey;
        this.header = header;
        this.vaultRevision = vaultRevision;
        this.lockHandle = lockHandle;
    }

    /** Creates a new vault file protected by a passphrase, returning an opened store.
     *
     * @param crypto the cryptographic service
     * @param file the vault file to create; must not already exist as a vault
     * @param passphrase caller-owned passphrase; wiped by the caller
     * @param clock the clock for timestamps
     * @return an opened store owning the new vault key
     */
    public static @NonNull OneFileVaultStore create(
            @NonNull DefaultCryptoService crypto,
            @NonNull Path file,
            char @NonNull [] passphrase,
            @NonNull Clock clock) {
        Objects.requireNonNull(crypto, "crypto");
        Objects.requireNonNull(file, "file");
        Objects.requireNonNull(passphrase, "passphrase");
        Objects.requireNonNull(clock, "clock");
        LockHandle lock = LockHandle.acquire(file);
        VaultKey dek = null;
        try {
            dek = crypto.generateVaultKey(new KeyId("vault-" + UUID.randomUUID()));
            byte[] salt = crypto.randomSalt();
            KdfParameters kdf = crypto.defaultArgon2idParameters(salt);
            VaultFingerprint fingerprint = crypto.deriveFingerprint(passphrase, kdf);
            byte[] wrapped = crypto.wrapVaultKey(dek, passphrase, kdf);
            KeySlot passphraseSlot =
                    new KeySlot(SlotType.PASSPHRASE, new KeyId("passphrase"), kdf, wrapped);
            Instant now = clock.instant();
            VaultHeader header =
                    new VaultHeader(
                            VaultFileFormat.FORMAT_VERSION,
                            fingerprint,
                            dek.keyId(),
                            List.of(passphraseSlot),
                            now,
                            now);
            reserveNewVaultFile(file);
            OneFileVaultStore store =
                    new OneFileVaultStore(file, crypto, clock, dek, header, 0L, lock);
            store.persist(header, now);
            dek = null;
            lock = null;
            return store;
        } finally {
            if (dek != null) {
                dek.close();
            }
            if (lock != null) {
                lock.close();
            }
        }
    }

    /** Opens an existing vault file with a passphrase, returning an opened store.
     *
     * @param crypto the cryptographic service
     * @param file the vault file to open
     * @param passphrase caller-owned passphrase; wiped by the caller
     * @param clock the clock for timestamps
     * @return an opened store owning the recovered vault key
     */
    public static @NonNull OneFileVaultStore open(
            @NonNull DefaultCryptoService crypto,
            @NonNull Path file,
            char @NonNull [] passphrase,
            @NonNull Clock clock) {
        Objects.requireNonNull(crypto, "crypto");
        Objects.requireNonNull(file, "file");
        Objects.requireNonNull(passphrase, "passphrase");
        Objects.requireNonNull(clock, "clock");
        LockHandle lock = LockHandle.acquire(file);
        VaultKey dek = null;
        try {
            byte[] bytes = readVaultFile(file);
            VaultFileFormat.OpenedFile opened = VaultFileFormat.open(crypto, bytes, passphrase);
            dek = opened.vaultKey();
            VaultContainerBody.Decoded body =
                    VaultContainerBody.decode(opened.containerBody(), opened.fingerprint());
            OneFileVaultStore store =
                    new OneFileVaultStore(
                            file, crypto, clock, dek, opened.header(), body.vaultRevision(), lock);
            dek = null;
            lock = null;
            for (EncryptedSecretRecord record : body.records()) {
                store.active.put(record.metadata().secretId(), record);
            }
            for (DeletedSecretRecord tombstone : body.tombstones()) {
                store.deleted.put(tombstone.secretId(), tombstone);
            }
            return store;
        } finally {
            if (dek != null) {
                dek.close();
            }
            if (lock != null) {
                lock.close();
            }
        }
    }

    /** Opens an existing vault file with a pre-recovered vault key for a passphrase-less device
     * open. The caller must have unwrapped the key from a {@link SlotType#DEVICE} slot. The store
     * takes ownership of the key on success; on failure the key is left open for the caller to close.
     *
     * @param crypto the cryptographic service
     * @param file the vault file to open
     * @param vaultKey the unlocked vault key
     * @param clock the clock for timestamps
     * @return an opened store owning the vault key
     */
    public static @NonNull OneFileVaultStore openWithVaultKey(
            @NonNull DefaultCryptoService crypto,
            @NonNull Path file,
            @NonNull VaultKey vaultKey,
            @NonNull Clock clock) {
        Objects.requireNonNull(crypto, "crypto");
        Objects.requireNonNull(file, "file");
        Objects.requireNonNull(vaultKey, "vaultKey");
        Objects.requireNonNull(clock, "clock");
        LockHandle lock = LockHandle.acquire(file);
        try {
            byte[] bytes = readVaultFile(file);
            VaultFileFormat.OpenedFile opened =
                    VaultFileFormat.openWithVaultKey(crypto, bytes, vaultKey);
            VaultContainerBody.Decoded body =
                    VaultContainerBody.decode(opened.containerBody(), opened.fingerprint());
            OneFileVaultStore store =
                    new OneFileVaultStore(
                            file,
                            crypto,
                            clock,
                            vaultKey,
                            opened.header(),
                            body.vaultRevision(),
                            lock);
            lock = null;
            for (EncryptedSecretRecord record : body.records()) {
                store.active.put(record.metadata().secretId(), record);
            }
            for (DeletedSecretRecord tombstone : body.tombstones()) {
                store.deleted.put(tombstone.secretId(), tombstone);
            }
            return store;
        } finally {
            if (lock != null) {
                lock.close();
            }
        }
    }

    /** Creates a new vault file from a pre-recovered vault key and a caller-built header, for
     * passphrase-less device provisioning. The header's vault key id must match the supplied
     * key. On success the store takes ownership of {@code vaultKey}; on failure {@code vaultKey} is left
     * open for the caller to close.
     *
     * @param crypto the cryptographic service
     * @param file the vault file to create; must not already exist as a vault
     * @param vaultKey the unlocked vault key recovered from a device slot
     * @param header the vault header to persist; its vault key id must match {@code vaultKey}
     * @param clock the clock for timestamps
     * @return an opened store owning the vault key
     */
    public static @NonNull OneFileVaultStore createWithVaultKey(
            @NonNull DefaultCryptoService crypto,
            @NonNull Path file,
            @NonNull VaultKey vaultKey,
            @NonNull VaultHeader header,
            @NonNull Clock clock) {
        Objects.requireNonNull(crypto, "crypto");
        Objects.requireNonNull(file, "file");
        Objects.requireNonNull(vaultKey, "vaultKey");
        Objects.requireNonNull(header, "header");
        Objects.requireNonNull(clock, "clock");
        if (!vaultKey.keyId().equals(header.vaultKeyId())) {
            throw new IllegalArgumentException("Vault key id does not match header vault key id");
        }
        LockHandle lock = LockHandle.acquire(file);
        try {
            reserveNewVaultFile(file);
            OneFileVaultStore store =
                    new OneFileVaultStore(file, crypto, clock, vaultKey, header, 0L, lock);
            store.persist(header, clock.instant());
            lock = null;
            return store;
        } finally {
            if (lock != null) {
                lock.close();
            }
        }
    }

    /** Returns the cryptographic service used by this store.
     *
     * @return the cryptographic service */
    public @NonNull DefaultCryptoService crypto() {
        return crypto;
    }

    /** Returns the vault fingerprint (non-secret routing identity from the header).
     *
     * @return the vault fingerprint */
    public @NonNull VaultFingerprint vaultFingerprint() {
        synchronized (this) {
            return header.fingerprint();
        }
    }

    /** Returns the active vault key id.
     *
     * @return the active key id */
    public @NonNull KeyId vaultKeyId() {
        synchronized (this) {
            return header.vaultKeyId();
        }
    }

    /** Returns the unlocked vault key. The key is owned by the store; callers must not close it.
     *
     * @return the store-owned unlocked key */
    public @NonNull VaultKey vaultKey() {
        synchronized (this) {
            requireOpen();
            return vaultKey;
        }
    }

    /** Returns the clock used by this store for timestamps.
     *
     * @return the store clock */
    public @NonNull Clock clock() {
        return clock;
    }

    /** Returns the current vault header. The header is immutable; a snapshot is returned so later
     * mutations do not affect the caller's reference.
     *
     * @return the current vault header */
    public @NonNull VaultHeader header() {
        synchronized (this) {
            requireOpen();
            return header;
        }
    }

    @Override
    public synchronized void saveVaultHeader(@NonNull VaultHeader header) {
        Objects.requireNonNull(header, "header");
        requireOpen();
        if (header.updatedAt().isBefore(this.header.updatedAt())) {
            throw new StoreException("Vault header updated time moved backwards", null);
        }
        if (!header.fingerprint().equals(this.header.fingerprint())) {
            throw new StoreException("Vault header fingerprint must not change", null);
        }
        mutate(() -> persist(header, header.updatedAt()));
    }

    @Override
    public synchronized @NonNull Optional<VaultHeader> loadVaultHeader() {
        requireOpen();
        return Optional.of(header);
    }

    @Override
    public synchronized long nextRevision() {
        requireOpen();
        return Math.addExact(vaultRevision, 1L);
    }

    @Override
    public synchronized void recordRevision(long revision) {
        requireOpen();
        if (revision < 0L) {
            throw new IllegalArgumentException("Revision must not be negative");
        }
        if (revision > vaultRevision) {
            mutate(
                    () -> {
                        vaultRevision = revision;
                        persist(header, clock.instant());
                    });
        }
    }

    @Override
    public synchronized void commitVaultKeyRotation(@NonNull VaultKeyRotation rotation) {
        Objects.requireNonNull(rotation, "rotation");
        requireOpen();
        if (mutationInProgress) {
            throw new IllegalStateException(
                    "Vault key rotation cannot be nested inside a mutation");
        }
        VaultKey oldKey = vaultKey;
        VaultHeader oldHeader = header;
        Map<SecretId, EncryptedSecretRecord> oldActive = new LinkedHashMap<>(active);
        long oldRevision = vaultRevision;
        vaultKey = rotation.nextVaultKey();
        header = rotation.header();
        active.clear();
        for (EncryptedSecretRecord record : rotation.activeRecords()) {
            active.put(record.metadata().secretId(), record);
            vaultRevision = Math.max(vaultRevision, record.revision());
        }
        try {
            persist(header, clock.instant());
        } catch (RuntimeException | Error e) {
            vaultKey = oldKey;
            header = oldHeader;
            vaultRevision = oldRevision;
            active.clear();
            active.putAll(oldActive);
            try {
                rotation.nextVaultKey().close();
            } catch (RuntimeException ignored) {
                // Best-effort cleanup of the orphaned target key.
            }
            throw e;
        }
        oldKey.close();
    }

    @Override
    public synchronized void saveSecretRecord(@NonNull EncryptedSecretRecord record) {
        Objects.requireNonNull(record, "record");
        requireOpen();
        mutate(
                () -> {
                    recordRevision(record.revision());
                    active.put(record.metadata().secretId(), record);
                    persist(header.withUpdatedAt(clock.instant()), clock.instant());
                });
    }

    @Override
    public synchronized @NonNull Optional<EncryptedSecretRecord> loadSecretRecord(
            @NonNull SecretId secretId) {
        Objects.requireNonNull(secretId, "secretId");
        requireOpen();
        EncryptedSecretRecord record = active.get(secretId);
        if (record == null) {
            return Optional.empty();
        }
        DeletedSecretRecord tombstone = deleted.get(secretId);
        if (tombstone != null && tombstone.revision() > record.revision()) {
            return Optional.empty();
        }
        return Optional.of(record);
    }

    @Override
    public synchronized void deleteSecretRecord(@NonNull SecretId secretId) {
        Objects.requireNonNull(secretId, "secretId");
        requireOpen();
        mutate(
                () -> {
                    active.remove(secretId);
                    persist(header.withUpdatedAt(clock.instant()), clock.instant());
                });
    }

    @Override
    public synchronized void saveDeletedSecretRecord(@NonNull DeletedSecretRecord record) {
        Objects.requireNonNull(record, "record");
        requireOpen();
        mutate(
                () -> {
                    recordRevision(record.revision());
                    deleted.put(record.secretId(), record);
                    persist(header.withUpdatedAt(clock.instant()), clock.instant());
                });
    }

    @Override
    public synchronized @NonNull Optional<DeletedSecretRecord> loadDeletedSecretRecord(
            @NonNull SecretId secretId) {
        Objects.requireNonNull(secretId, "secretId");
        requireOpen();
        DeletedSecretRecord tombstone = deleted.get(secretId);
        if (tombstone == null) {
            return Optional.empty();
        }
        EncryptedSecretRecord record = active.get(secretId);
        if (record != null && record.revision() > tombstone.revision()) {
            return Optional.empty();
        }
        return Optional.of(tombstone);
    }

    @Override
    public synchronized void deleteDeletedSecretRecord(@NonNull SecretId secretId) {
        Objects.requireNonNull(secretId, "secretId");
        requireOpen();
        mutate(
                () -> {
                    deleted.remove(secretId);
                    persist(header.withUpdatedAt(clock.instant()), clock.instant());
                });
    }

    @Override
    public synchronized @NonNull List<SecretMetadata> listMetadata() {
        requireOpen();
        return listSecretRecords().stream().map(EncryptedSecretRecord::metadata).toList();
    }

    @Override
    public synchronized @NonNull List<EncryptedSecretRecord> listSecretRecords() {
        requireOpen();
        List<EncryptedSecretRecord> records = new ArrayList<>(active.size());
        for (EncryptedSecretRecord record : active.values()) {
            DeletedSecretRecord tombstone = deleted.get(record.metadata().secretId());
            if (tombstone != null && tombstone.revision() > record.revision()) {
                continue;
            }
            records.add(record);
        }
        records.sort(
                Comparator.comparing(
                        record -> record.metadata().secretId(), SecretIdComparator.INSTANCE));
        return Collections.unmodifiableList(records);
    }

    @Override
    public synchronized @NonNull List<DeletedSecretRecord> listDeletedSecretRecords() {
        requireOpen();
        List<DeletedSecretRecord> tombstones = new ArrayList<>(deleted.size());
        for (DeletedSecretRecord tombstone : deleted.values()) {
            EncryptedSecretRecord record = active.get(tombstone.secretId());
            if (record != null && record.revision() > tombstone.revision()) {
                continue;
            }
            tombstones.add(tombstone);
        }
        tombstones.sort(
                Comparator.comparing(DeletedSecretRecord::secretId, SecretIdComparator.INSTANCE));
        return Collections.unmodifiableList(tombstones);
    }

    /** Closes the store, destroying the vault key material and releasing the file locks. */
    @Override
    public synchronized void close() {
        if (closed) {
            return;
        }
        closed = true;
        try {
            vaultKey.close();
        } finally {
            lockHandle.close();
        }
    }

    private void requireOpen() {
        if (closed) {
            throw new IllegalStateException("Vault store is closed");
        }
    }

    @Override
    public synchronized void commitMutation(@NonNull VaultMutation mutation) {
        Objects.requireNonNull(mutation, "mutation");
        requireOpen();
        mutate(() -> mutation.commit(nextRevision()));
    }

    /** Defer all writes in a compound mutation and restore every live field on failure. */
    private void mutate(@NonNull Runnable action) {
        if (mutationInProgress) {
            action.run();
            return;
        }
        VaultHeader previousHeader = header;
        long previousRevision = vaultRevision;
        Map<SecretId, EncryptedSecretRecord> previousActive = new LinkedHashMap<>(active);
        Map<SecretId, DeletedSecretRecord> previousDeleted = new LinkedHashMap<>(deleted);
        mutationInProgress = true;
        persistenceRequested = false;
        try {
            action.run();
            if (persistenceRequested) {
                persistNow(header, clock.instant());
            }
        } catch (RuntimeException | Error error) {
            header = previousHeader;
            vaultRevision = previousRevision;
            active.clear();
            active.putAll(previousActive);
            deleted.clear();
            deleted.putAll(previousDeleted);
            throw error;
        } finally {
            mutationInProgress = false;
            persistenceRequested = false;
        }
    }

    private void persist(@NonNull VaultHeader headerToWrite, @NonNull Instant encryptedAt) {
        if (mutationInProgress) {
            header = headerToWrite;
            persistenceRequested = true;
            return;
        }
        persistNow(headerToWrite, encryptedAt);
    }

    private void persistNow(@NonNull VaultHeader headerToWrite, @NonNull Instant encryptedAt) {
        byte[] body =
                VaultContainerBody.encode(
                        vaultRevision, List.copyOf(active.values()), List.copyOf(deleted.values()));
        byte[] bytes = VaultFileFormat.write(crypto, headerToWrite, vaultKey, body, encryptedAt);
        atomicWrite(bytes);
        this.header = headerToWrite;
    }

    /**
     * Installs a complete staging file at a new vault path while holding the target vault lock.
     * Existing destinations are never replaced. Filesystems without hard links use a CREATE_NEW
     * copy; the lock prevents another Core opener from observing an incomplete file.
     *
     * @param source complete staging vault, retained for the caller to clean up
     * @param target new destination vault path
     */
    public static void installNewVaultFile(@NonNull Path source, @NonNull Path target) {
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(target, "target");
        try (LockHandle ignored = LockHandle.acquire(target)) {
            try {
                Files.createLink(target, source);
                return;
            } catch (FileAlreadyExistsException error) {
                throw new StoreException("Vault restore target already exists: " + target, error);
            } catch (IOException | UnsupportedOperationException noHardLink) {
                boolean created = false;
                try {
                    try (FileChannel output =
                            FileChannel.open(
                                    target,
                                    StandardOpenOption.CREATE_NEW,
                                    StandardOpenOption.WRITE)) {
                        created = true;
                        try (FileChannel input =
                                FileChannel.open(source, StandardOpenOption.READ)) {
                            ByteBuffer buffer = ByteBuffer.allocate(8192);
                            while (input.read(buffer) != -1) {
                                buffer.flip();
                                while (buffer.hasRemaining()) {
                                    output.write(buffer);
                                }
                                buffer.clear();
                            }
                            output.force(true);
                        }
                    }
                } catch (IOException | RuntimeException | Error error) {
                    if (created) {
                        try {
                            Files.deleteIfExists(target);
                        } catch (IOException cleanup) {
                            error.addSuppressed(cleanup);
                        }
                    }
                    throw new StoreException("Could not install new vault file: " + target, error);
                }
            }
        }
    }

    private static void rejectSymbolicLink(@NonNull Path file) {
        if (Files.isSymbolicLink(file)) {
            throw new StoreException("Vault file must not be a symbolic link: " + file, null);
        }
    }

    private static void reserveNewVaultFile(@NonNull Path file) {
        try {
            Files.createFile(file);
        } catch (FileAlreadyExistsException error) {
            throw new StoreException("Vault file already exists: " + file, error);
        } catch (IOException error) {
            throw new StoreException("Could not reserve new vault file: " + file, error);
        }
    }

    private void atomicWrite(byte @NonNull [] bytes) {
        rejectSymbolicLink(file);
        Path temp = file.resolveSibling(file.getFileName() + ".tmp-" + UUID.randomUUID());
        try {
            try (FileChannel channel =
                    FileChannel.open(
                            temp,
                            StandardOpenOption.CREATE,
                            StandardOpenOption.WRITE,
                            StandardOpenOption.TRUNCATE_EXISTING)) {
                ByteBuffer src = ByteBuffer.wrap(bytes);
                while (src.hasRemaining()) {
                    channel.write(src);
                }
                channel.force(true);
            }
            try {
                Files.move(
                        temp,
                        file,
                        StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
            }
            syncParentDirectory();
        } catch (IOException e) {
            throw new StoreException("Could not write vault file: " + file, e);
        } finally {
            try {
                Files.deleteIfExists(temp);
            } catch (IOException ignored) {
                // Best-effort cleanup of an abandoned temp file.
            }
        }
    }

    private void syncParentDirectory() {
        Path parent = file.getParent();
        if (parent == null) {
            return;
        }
        try (FileChannel channel = FileChannel.open(parent, StandardOpenOption.READ)) {
            channel.force(true);
        } catch (IOException | UnsupportedOperationException e) {
            // Directory fsync is best-effort and unsupported on some platforms.
        }
    }

    private static byte @NonNull [] readVaultFile(@NonNull Path file) {
        try {
            return Files.readAllBytes(file);
        } catch (NoSuchFileException e) {
            throw new StoreException("Vault file does not exist: " + file, e);
        } catch (IOException e) {
            throw new StoreException("Could not read vault file: " + file, e);
        }
    }

    /** A held process token and exclusive file lock for a vault file. */
    private static final class LockHandle implements AutoCloseable {
        private final Path canonical;
        private final Object processToken;
        private final @Nullable FileChannel channel;
        private final @Nullable FileLock fileLock;

        private LockHandle(
                @NonNull Path canonical,
                @NonNull Object processToken,
                @Nullable FileChannel channel,
                @Nullable FileLock fileLock) {
            this.canonical = canonical;
            this.processToken = processToken;
            this.channel = channel;
            this.fileLock = fileLock;
        }

        static @NonNull LockHandle acquire(@NonNull Path file) {
            rejectSymbolicLink(file);
            Path canonical = file.toAbsolutePath().normalize();
            Object token = new Object();
            if (PROCESS_LOCKS.putIfAbsent(canonical, token) != null) {
                throw new StoreException(
                        "Vault file is already open in this process: " + canonical, null);
            }
            Path lockPath = file.resolveSibling(file.getFileName() + ".lock");
            FileChannel channel = null;
            FileLock lock = null;
            try {
                channel =
                        FileChannel.open(
                                lockPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
                lock = channel.tryLock();
                if (lock == null) {
                    throw new StoreException(
                            "Vault file is locked by another process: " + lockPath, null);
                }
            } catch (IOException e) {
                closeQuietly(channel);
                PROCESS_LOCKS.remove(canonical, token);
                throw new StoreException("Could not acquire vault file lock: " + lockPath, e);
            } catch (RuntimeException e) {
                closeQuietly(channel);
                PROCESS_LOCKS.remove(canonical, token);
                throw e;
            }
            return new LockHandle(canonical, token, channel, lock);
        }

        @Override
        public void close() {
            if (fileLock != null) {
                try {
                    fileLock.release();
                } catch (IOException ignored) {
                    // Best-effort lock release.
                }
            }
            closeQuietly(channel);
            PROCESS_LOCKS.remove(canonical, processToken);
        }
    }

    private static void closeQuietly(@Nullable FileChannel channel) {
        if (channel != null) {
            try {
                channel.close();
            } catch (IOException ignored) {
                // Best-effort channel close.
            }
        }
    }

    /** Comparator for {@link SecretId} by its {@link UUID} natural order. */
    private static final class SecretIdComparator implements Comparator<SecretId> {
        static final SecretIdComparator INSTANCE = new SecretIdComparator();

        @Override
        public int compare(@NonNull SecretId left, @NonNull SecretId right) {
            return left.value().compareTo(right.value());
        }
    }
}
