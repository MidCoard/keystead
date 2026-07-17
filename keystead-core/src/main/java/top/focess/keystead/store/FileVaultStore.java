package top.focess.keystead.store;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Collectors;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.crypto.KdfParameters;
import top.focess.keystead.memory.WipeableByteArrayOutputStream;
import top.focess.keystead.model.*;

public final class FileVaultStore implements VaultStore {

    private static final String VAULT_FILE = "vault.properties";
    private static final String REVISION_FILE = "revisions.properties";
    private static final String LOCK_FILE = ".keystead.lock";
    private static final String ROTATION_JOURNAL_FILE = ".keystead-rotation.properties";
    private static final String ROTATION_STAGE_DIRECTORY = ".keystead-rotation-stage";
    private static final String ROTATION_BACKUP_DIRECTORY = ".keystead-rotation-backup";
    private static final String KDF_PARAMETER_PREFIX = "kdf.parameter.";
    private static final int MAX_ENCODED_KDF_SALT_CHARACTERS =
            ((SecurityLimits.MAX_KDF_SALT_BYTES + 2) / 3) * 4;
    private static final ConcurrentMap<Path, Object> PROCESS_LOCKS = new ConcurrentHashMap<>();

    private final Path vaultDirectory;
    private final Path secretsDirectory;
    private final Path deletedDirectory;
    private final Path revisionPath;
    private final Path lockPath;
    private final FileDurability durability;
    private final Base64ValueDecoder base64Decoder;

    public FileVaultStore(@NonNull Path vaultDirectory) {
        this(
                vaultDirectory,
                FileVaultStore::forcePath,
                (field, value) -> Base64.getDecoder().decode(value));
    }

    FileVaultStore(@NonNull Path vaultDirectory, @NonNull FileDurability durability) {
        this(vaultDirectory, durability, (field, value) -> Base64.getDecoder().decode(value));
    }

    FileVaultStore(
            @NonNull Path vaultDirectory,
            @NonNull FileDurability durability,
            @NonNull Base64ValueDecoder base64Decoder) {
        this.vaultDirectory =
                Objects.requireNonNull(vaultDirectory, "vaultDirectory")
                        .toAbsolutePath()
                        .normalize();
        this.durability = Objects.requireNonNull(durability, "durability");
        this.base64Decoder = Objects.requireNonNull(base64Decoder, "base64Decoder");
        this.secretsDirectory = this.vaultDirectory.resolve("secrets");
        this.deletedDirectory = this.vaultDirectory.resolve("deleted");
        this.revisionPath = this.vaultDirectory.resolve(REVISION_FILE);
        this.lockPath = this.vaultDirectory.resolve(LOCK_FILE);
    }

    @Override
    public void saveVaultHeader(@NonNull VaultHeader header) {
        Objects.requireNonNull(header, "header");
        Path path = vaultDirectory.resolve(VAULT_FILE);
        if (exists(path)) {
            VaultHeader existing = readHeader(load(path));
            if (!existing.vaultId().equals(header.vaultId())) {
                throw new StoreException("Vault directory already belongs to another vault", null);
            }
            if (header.updatedAt().isBefore(existing.updatedAt())) {
                throw new StoreException("Vault header updated time must not move backwards", null);
            }
        }
        requireStoredRowsBelongTo(header.vaultId(), secretsDirectory, "secret");
        requireStoredRowsBelongTo(header.vaultId(), deletedDirectory, "tombstone");
        Properties properties = new SortedProperties();
        properties.setProperty("vaultId", header.vaultId().value().toString());
        properties.setProperty("formatVersion", Integer.toString(header.formatVersion()));
        properties.setProperty("kdfAlgorithm", header.kdfAlgorithm());
        properties.setProperty("kdfSalt", b64(header.kdfSalt()));
        properties.setProperty("kdfIterations", Integer.toString(header.kdfIterations()));
        writeKdfParameters(properties, header.kdfParameters());
        properties.setProperty("vaultKeyId", header.vaultKeyId().value());
        properties.setProperty("wrappedVaultKey", b64(header.wrappedVaultKey()));
        properties.setProperty("createdAt", header.createdAt().toString());
        properties.setProperty("updatedAt", header.updatedAt().toString());
        store(properties, path);
    }

    @Override
    public @NonNull Optional<VaultHeader> loadVaultHeader(@NonNull VaultId vaultId) {
        Objects.requireNonNull(vaultId, "vaultId");
        recoverRotation();
        Path path = vaultDirectory.resolve(VAULT_FILE);
        if (!exists(path)) {
            return Optional.empty();
        }
        Properties properties = load(path);
        VaultHeader header = readHeader(properties);
        if (!header.vaultId().equals(vaultId)) {
            return Optional.empty();
        }
        return Optional.of(header);
    }

    @Override
    public synchronized long nextRevision(@NonNull VaultId vaultId) {
        Objects.requireNonNull(vaultId, "vaultId");
        requireVaultDirectoryIdentity(vaultId);
        return currentRevision(vaultId) + 1;
    }

    @Override
    public synchronized void recordRevision(@NonNull VaultId vaultId, long revision) {
        Objects.requireNonNull(vaultId, "vaultId");
        requireVaultDirectoryIdentity(vaultId);
        if (revision < 0) {
            throw new IllegalArgumentException("Record revision must not be negative");
        }
        if (revision > currentRevision(vaultId)) {
            writeRevision(vaultId, revision);
        }
    }

    @Override
    public void commitMutation(@NonNull VaultId vaultId, @NonNull VaultMutation mutation) {
        Objects.requireNonNull(vaultId, "vaultId");
        Objects.requireNonNull(mutation, "mutation");
        synchronized (processLock(lockPath)) {
            try {
                requireVaultDirectoryIdentity(vaultId);
                createDirectories(vaultDirectory);
                try (FileChannel channel =
                                FileChannel.open(
                                        requireManagedPath(lockPath),
                                        StandardOpenOption.CREATE,
                                        StandardOpenOption.WRITE);
                        FileLock lock = channel.lock()) {
                    recoverVaultFiles(vaultId);
                    mutation.commit(nextRevision(vaultId));
                    channel.force(true);
                }
            } catch (IOException e) {
                throw new StoreException("Could not lock vault mutation", e);
            }
        }
    }

    @Override
    public void commitVaultKeyRotation(@NonNull VaultKeyRotation rotation) {
        Objects.requireNonNull(rotation, "rotation");
        VaultId vaultId = rotation.header().vaultId();
        synchronized (processLock(lockPath)) {
            try {
                requireVaultDirectoryIdentity(vaultId);
                createDirectories(vaultDirectory);
                try (FileChannel channel =
                                FileChannel.open(
                                        requireManagedPath(lockPath),
                                        StandardOpenOption.CREATE,
                                        StandardOpenOption.WRITE);
                        FileLock lock = channel.lock()) {
                    recoverRotation();
                    Path stage = vaultDirectory.resolve(ROTATION_STAGE_DIRECTORY);
                    Path backup = vaultDirectory.resolve(ROTATION_BACKUP_DIRECTORY);
                    deleteDirectory(stage);
                    deleteDirectory(backup);
                    createDirectories(stage.resolve("secrets"));
                    writeHeader(rotation.header(), stage.resolve(VAULT_FILE));
                    for (EncryptedSecretRecord record : rotation.activeRecords())
                        writeRecord(
                                record,
                                stage.resolve("secrets")
                                        .resolve(record.metadata().id().value() + ".properties"));
                    Properties journal = new Properties();
                    journal.setProperty("state", "PREPARED");
                    store(journal, vaultDirectory.resolve(ROTATION_JOURNAL_FILE));
                    createDirectories(backup);
                    moveIfExists(vaultDirectory.resolve(VAULT_FILE), backup.resolve(VAULT_FILE));
                    moveIfExists(secretsDirectory, backup.resolve("secrets"));
                    moveIfExists(stage.resolve(VAULT_FILE), vaultDirectory.resolve(VAULT_FILE));
                    moveIfExists(stage.resolve("secrets"), secretsDirectory);
                    journal.setProperty("state", "COMMITTED");
                    store(journal, vaultDirectory.resolve(ROTATION_JOURNAL_FILE));
                    deleteDirectory(backup);
                    deleteDirectory(stage);
                    deleteIfExistsDurably(vaultDirectory.resolve(ROTATION_JOURNAL_FILE));
                    channel.force(true);
                }
            } catch (IOException e) {
                throw new StoreException("Could not commit vault key rotation", e);
            }
        }
    }

    @Override
    public void saveSecretRecord(@NonNull EncryptedSecretRecord record) {
        Objects.requireNonNull(record, "record");
        requireVaultDirectoryIdentity(record.vaultId());
        Optional<EncryptedSecretRecord> existing =
                loadStoredSecretRecord(record.vaultId(), record.metadata().id());
        if (existing.isPresent() && existing.get().revision() >= record.revision()) {
            return;
        }
        Optional<DeletedSecretRecord> deleted =
                loadStoredDeletedSecretRecord(record.vaultId(), record.metadata().id());
        if (deleted.isPresent() && deleted.get().revision() >= record.revision()) {
            return;
        }
        Properties properties = new Properties();
        writeMetadata(properties, record.vaultId(), record.metadata());
        properties.setProperty("record.revision", Long.toString(record.revision()));
        EncryptedEnvelope envelope = record.payload();
        properties.setProperty("envelope.version", Integer.toString(envelope.version()));
        properties.setProperty("envelope.algorithm", envelope.algorithm());
        properties.setProperty("envelope.keyId", envelope.keyId().value());
        properties.setProperty("envelope.nonce", b64(envelope.nonce()));
        properties.setProperty("envelope.ciphertext", b64(envelope.ciphertext()));
        properties.setProperty("envelope.encryptedAt", envelope.encryptedAt().toString());
        store(properties, secretPath(record.metadata().id()));
        deleteDeletedSecretRecord(record.vaultId(), record.metadata().id());
        recordRevision(record.vaultId(), record.revision());
    }

    @Override
    public @NonNull Optional<EncryptedSecretRecord> loadSecretRecord(
            @NonNull VaultId vaultId, @NonNull SecretId secretId) {
        Objects.requireNonNull(vaultId, "vaultId");
        Objects.requireNonNull(secretId, "secretId");
        requireVaultDirectoryIdentity(vaultId);
        return loadStoredSecretRecord(vaultId, secretId)
                .filter(record -> !isHiddenByNewerTombstone(record));
    }

    private @NonNull Optional<EncryptedSecretRecord> loadStoredSecretRecord(
            @NonNull VaultId vaultId, @NonNull SecretId secretId) {
        Path path = secretPath(secretId);
        if (!exists(path)) {
            return Optional.empty();
        }
        Properties properties = load(path);
        VaultId storedVaultId = new VaultId(UUID.fromString(required(properties, "vaultId")));
        if (!storedVaultId.equals(vaultId)) {
            return Optional.empty();
        }
        SecretMetadata metadata = readMetadata(properties);
        long recordRevision = longValue(properties, "record.revision");
        requireSecretPathMatches(secretId, metadata.id(), "Secret record");
        EncryptedEnvelope envelope =
                new EncryptedEnvelope(
                        intValue(properties, "envelope.version"),
                        required(properties, "envelope.algorithm"),
                        new KeyId(required(properties, "envelope.keyId")),
                        bytes(properties, "envelope.nonce"),
                        envelopeAad(properties, storedVaultId, metadata, recordRevision),
                        boundedBytes(
                                properties,
                                "envelope.ciphertext",
                                SecurityLimits.MAX_ENVELOPE_CIPHERTEXT_BYTES,
                                "Vault envelope ciphertext"),
                        Instant.parse(required(properties, "envelope.encryptedAt")));
        EncryptedSecretRecord record =
                new EncryptedSecretRecord(storedVaultId, metadata, envelope, recordRevision);
        return Optional.of(record);
    }

    @Override
    public void deleteSecretRecord(@NonNull VaultId vaultId, @NonNull SecretId secretId) {
        Objects.requireNonNull(vaultId, "vaultId");
        Objects.requireNonNull(secretId, "secretId");
        requireVaultDirectoryIdentity(vaultId);
        if (loadStoredSecretRecord(vaultId, secretId).isEmpty()) {
            return;
        }
        try {
            deleteIfExistsDurably(secretPath(secretId));
        } catch (IOException e) {
            throw new StoreException("Could not delete secret record", e);
        }
    }

    @Override
    public void saveDeletedSecretRecord(@NonNull DeletedSecretRecord record) {
        Objects.requireNonNull(record, "record");
        requireVaultDirectoryIdentity(record.vaultId());
        Optional<DeletedSecretRecord> deleted =
                loadStoredDeletedSecretRecord(record.vaultId(), record.secretId());
        if (deleted.isPresent() && deleted.get().revision() >= record.revision()) {
            return;
        }
        Optional<EncryptedSecretRecord> existing =
                loadStoredSecretRecord(record.vaultId(), record.secretId());
        if (existing.isPresent() && existing.get().revision() > record.revision()) {
            return;
        }
        Properties properties = new Properties();
        properties.setProperty("vaultId", record.vaultId().value().toString());
        properties.setProperty("secretId", record.secretId().value().toString());
        properties.setProperty("secretType", record.secretType().name());
        properties.setProperty("revision", Long.toString(record.revision()));
        properties.setProperty("deletedAt", record.deletedAt().toString());
        store(properties, deletedPath(record.secretId()));
        deleteSecretRecord(record.vaultId(), record.secretId());
        recordRevision(record.vaultId(), record.revision());
    }

    @Override
    public @NonNull Optional<DeletedSecretRecord> loadDeletedSecretRecord(
            @NonNull VaultId vaultId, @NonNull SecretId secretId) {
        Objects.requireNonNull(vaultId, "vaultId");
        Objects.requireNonNull(secretId, "secretId");
        requireVaultDirectoryIdentity(vaultId);
        return loadStoredDeletedSecretRecord(vaultId, secretId)
                .filter(record -> !isHiddenByNewerRecord(record));
    }

    private @NonNull Optional<DeletedSecretRecord> loadStoredDeletedSecretRecord(
            @NonNull VaultId vaultId, @NonNull SecretId secretId) {
        Path path = deletedPath(secretId);
        if (!exists(path)) {
            return Optional.empty();
        }
        DeletedSecretRecord record = readDeletedRecord(load(path));
        if (!record.vaultId().equals(vaultId)) {
            return Optional.empty();
        }
        requireSecretPathMatches(secretId, record.secretId(), "Deleted secret record");
        return Optional.of(record);
    }

    @Override
    public void deleteDeletedSecretRecord(@NonNull VaultId vaultId, @NonNull SecretId secretId) {
        Objects.requireNonNull(vaultId, "vaultId");
        Objects.requireNonNull(secretId, "secretId");
        requireVaultDirectoryIdentity(vaultId);
        if (loadStoredDeletedSecretRecord(vaultId, secretId).isEmpty()) {
            return;
        }
        try {
            deleteIfExistsDurably(deletedPath(secretId));
        } catch (IOException e) {
            throw new StoreException("Could not delete tombstone record", e);
        }
    }

    @Override
    public @NonNull List<SecretMetadata> listMetadata(@NonNull VaultId vaultId) {
        Objects.requireNonNull(vaultId, "vaultId");
        return listSecretRecords(vaultId).stream().map(EncryptedSecretRecord::metadata).toList();
    }

    @Override
    public @NonNull List<EncryptedSecretRecord> listSecretRecords(@NonNull VaultId vaultId) {
        Objects.requireNonNull(vaultId, "vaultId");
        requireVaultDirectoryIdentity(vaultId);
        return listStoredSecretRecords(vaultId).stream()
                .filter(record -> !isHiddenByNewerTombstone(record))
                .sorted(Comparator.comparing(record -> record.metadata().id().value()))
                .toList();
    }

    private @NonNull List<EncryptedSecretRecord> listStoredSecretRecords(@NonNull VaultId vaultId) {
        if (!exists(secretsDirectory)) {
            return List.of();
        }
        try (var stream = Files.list(requireManagedPath(secretsDirectory))) {
            return stream.filter(path -> path.getFileName().toString().endsWith(".properties"))
                    .map(this::requireManagedPath)
                    .map(path -> readRecordSafely(path, vaultId))
                    .flatMap(Optional::stream)
                    .toList();
        } catch (IOException e) {
            throw new StoreException("Could not list secret records", e);
        }
    }

    private @NonNull Optional<EncryptedSecretRecord> readRecordSafely(
            @NonNull Path path, @NonNull VaultId vaultId) {
        try {
            Properties properties = load(path);
            if (!vaultId.value().toString().equals(properties.getProperty("vaultId"))) {
                return Optional.empty();
            }
            EncryptedSecretRecord record = readRecord(properties);
            requireSecretPathMatches(
                    secretIdFromRowPath(path), record.metadata().id(), "Secret record");
            return Optional.of(record);
        } catch (StoreException | IllegalArgumentException e) {
            // A single corrupt/truncated record must not brick the whole vault listing.
            return Optional.empty();
        }
    }

    @Override
    public @NonNull List<DeletedSecretRecord> listDeletedSecretRecords(@NonNull VaultId vaultId) {
        Objects.requireNonNull(vaultId, "vaultId");
        requireVaultDirectoryIdentity(vaultId);
        return listStoredDeletedSecretRecords(vaultId).stream()
                .filter(record -> !isHiddenByNewerRecord(record))
                .sorted(Comparator.comparing(record -> record.secretId().value()))
                .toList();
    }

    private @NonNull List<DeletedSecretRecord> listStoredDeletedSecretRecords(
            @NonNull VaultId vaultId) {
        if (!exists(deletedDirectory)) {
            return List.of();
        }
        try (var stream = Files.list(requireManagedPath(deletedDirectory))) {
            return stream.filter(path -> path.getFileName().toString().endsWith(".properties"))
                    .map(this::requireManagedPath)
                    .map(path -> readDeletedRecordSafely(path, vaultId))
                    .flatMap(Optional::stream)
                    .toList();
        } catch (IOException e) {
            throw new StoreException("Could not list deleted secret records", e);
        }
    }

    private @NonNull Optional<DeletedSecretRecord> readDeletedRecordSafely(
            @NonNull Path path, @NonNull VaultId vaultId) {
        try {
            Properties properties = load(path);
            if (!vaultId.value().toString().equals(properties.getProperty("vaultId"))) {
                return Optional.empty();
            }
            DeletedSecretRecord record = readDeletedRecord(properties);
            requireSecretPathMatches(
                    secretIdFromRowPath(path), record.secretId(), "Deleted secret record");
            return Optional.of(record);
        } catch (StoreException | IllegalArgumentException e) {
            // A single corrupt tombstone must not brick the whole vault listing.
            return Optional.empty();
        }
    }

    private @NonNull EncryptedSecretRecord readRecord(@NonNull Properties properties) {
        VaultId storedVaultId = new VaultId(UUID.fromString(required(properties, "vaultId")));
        SecretMetadata metadata = readMetadata(properties);
        long recordRevision = longValue(properties, "record.revision");
        EncryptedEnvelope envelope =
                new EncryptedEnvelope(
                        intValue(properties, "envelope.version"),
                        required(properties, "envelope.algorithm"),
                        new KeyId(required(properties, "envelope.keyId")),
                        bytes(properties, "envelope.nonce"),
                        envelopeAad(properties, storedVaultId, metadata, recordRevision),
                        boundedBytes(
                                properties,
                                "envelope.ciphertext",
                                SecurityLimits.MAX_ENVELOPE_CIPHERTEXT_BYTES,
                                "Vault envelope ciphertext"),
                        Instant.parse(required(properties, "envelope.encryptedAt")));
        EncryptedSecretRecord record =
                new EncryptedSecretRecord(storedVaultId, metadata, envelope, recordRevision);
        return record;
    }

    private byte @NonNull [] envelopeAad(
            @NonNull Properties properties,
            @NonNull VaultId vaultId,
            @NonNull SecretMetadata metadata,
            long recordRevision) {
        @Nullable String encoded = properties.getProperty("envelope.aad");
        if (encoded != null) {
            return boundedBytes(
                    "envelope.aad",
                    encoded,
                    SecurityLimits.MAX_ENVELOPE_AAD_BYTES,
                    "Vault envelope AAD");
        }
        return SecretRecordAad.encode(vaultId, metadata, recordRevision);
    }

    private boolean isHiddenByNewerTombstone(@NonNull EncryptedSecretRecord record) {
        try {
            return loadDeletedSecretRecord(record.vaultId(), record.metadata().id())
                    .filter(deleted -> deleted.revision() >= record.revision())
                    .isPresent();
        } catch (StoreException | IllegalArgumentException e) {
            return false;
        }
    }

    private boolean isHiddenByNewerRecord(@NonNull DeletedSecretRecord record) {
        try {
            return loadStoredSecretRecord(record.vaultId(), record.secretId())
                    .filter(active -> active.revision() > record.revision())
                    .isPresent();
        } catch (StoreException | IllegalArgumentException e) {
            return false;
        }
    }

    private @NonNull DeletedSecretRecord readDeletedRecord(@NonNull Properties properties) {
        return new DeletedSecretRecord(
                new VaultId(UUID.fromString(required(properties, "vaultId"))),
                new SecretId(UUID.fromString(required(properties, "secretId"))),
                SecretType.valueOf(required(properties, "secretType")),
                longValue(properties, "revision"),
                Instant.parse(required(properties, "deletedAt")));
    }

    private void writeMetadata(
            @NonNull Properties properties,
            @NonNull VaultId vaultId,
            @NonNull SecretMetadata metadata) {
        properties.setProperty("vaultId", vaultId.value().toString());
        properties.setProperty("metadata.id", metadata.id().value().toString());
        properties.setProperty("metadata.type", metadata.type().name());
        properties.setProperty("metadata.title", b64(metadata.title()));
        writeClassification(properties, metadata.classification());
        properties.setProperty(
                "metadata.tags",
                metadata.tags().stream().sorted().map(this::b64).collect(Collectors.joining(",")));
        properties.setProperty("metadata.attributes", encodedMap(metadata.profile().attributes()));
        properties.setProperty("metadata.createdAt", metadata.createdAt().toString());
        properties.setProperty("metadata.updatedAt", metadata.updatedAt().toString());
        properties.setProperty("metadata.revision", Long.toString(metadata.revision()));
    }

    private @NonNull SecretMetadata readMetadata(@NonNull Properties properties) {
        return new SecretMetadata(
                new SecretId(UUID.fromString(required(properties, "metadata.id"))),
                SecretType.valueOf(required(properties, "metadata.type")),
                new SecretProfile(
                        text(properties, "metadata.title"),
                        readClassification(properties),
                        tags(properties),
                        encodedMap(properties.getProperty("metadata.attributes", ""))),
                Instant.parse(required(properties, "metadata.createdAt")),
                Instant.parse(required(properties, "metadata.updatedAt")),
                longValue(properties, "metadata.revision"));
    }

    private void writeClassification(
            @NonNull Properties properties, @NonNull SecretClassification classification) {
        setNullableText(properties, "metadata.classification.category", classification.category());
        setNullableText(properties, "metadata.classification.provider", classification.provider());
        setNullableText(properties, "metadata.classification.software", classification.software());
        setNullableText(properties, "metadata.classification.account", classification.account());
        properties.setProperty(
                "metadata.classification.labels",
                classification.labels().stream()
                        .sorted()
                        .map(this::b64)
                        .collect(Collectors.joining(",")));
    }

    private @NonNull SecretClassification readClassification(@NonNull Properties properties) {
        return new SecretClassification(
                optionalText(properties, "metadata.classification.category"),
                optionalText(properties, "metadata.classification.provider"),
                optionalText(properties, "metadata.classification.software"),
                optionalText(properties, "metadata.classification.account"),
                encodedSet(properties.getProperty("metadata.classification.labels", "")));
    }

    private @NonNull VaultHeader readHeader(@NonNull Properties properties) {
        return new VaultHeader(
                new VaultId(UUID.fromString(required(properties, "vaultId"))),
                intValue(properties, "formatVersion"),
                readKdfParameters(properties),
                new KeyId(required(properties, "vaultKeyId")),
                boundedBytes(
                        properties,
                        "wrappedVaultKey",
                        SecurityLimits.MAX_WRAPPED_KEY_PACKAGE_BYTES,
                        "Vault wrapped key package"),
                Instant.parse(required(properties, "createdAt")),
                Instant.parse(required(properties, "updatedAt")));
    }

    private void requireVaultDirectoryIdentity(@NonNull VaultId vaultId) {
        Path path = vaultDirectory.resolve(VAULT_FILE);
        if (!exists(path)) {
            return;
        }
        VaultHeader header = readHeader(load(path));
        if (!header.vaultId().equals(vaultId)) {
            throw new StoreException("Vault directory already belongs to another vault", null);
        }
    }

    private void requireStoredRowsBelongTo(
            @NonNull VaultId vaultId, @NonNull Path directory, @NonNull String rowKind) {
        if (!exists(directory)) {
            return;
        }
        try (var stream = Files.list(requireManagedPath(directory))) {
            stream.filter(path -> path.getFileName().toString().endsWith(".properties"))
                    .map(this::requireManagedPath)
                    .forEach(path -> requireStoredRowBelongsTo(vaultId, rowKind, path));
        } catch (IOException e) {
            throw new StoreException("Could not inspect existing vault " + rowKind + " rows", e);
        }
    }

    private void requireStoredRowBelongsTo(
            @NonNull VaultId vaultId, @NonNull String rowKind, @NonNull Path path) {
        Properties properties = load(path);
        @Nullable String storedVaultId = properties.getProperty("vaultId");
        if (storedVaultId == null) {
            throw new StoreException(
                    "Vault directory contains " + rowKind + " rows without a vault identity", null);
        }
        if (!storedVaultId.equals(vaultId.value().toString())) {
            throw new StoreException(
                    "Vault directory contains " + rowKind + " rows for another vault", null);
        }
    }

    private @NonNull Path secretPath(@NonNull SecretId secretId) {
        return secretsDirectory.resolve(secretId.value() + ".properties");
    }

    private @NonNull Path deletedPath(@NonNull SecretId secretId) {
        return deletedDirectory.resolve(secretId.value() + ".properties");
    }

    private @NonNull SecretId secretIdFromRowPath(@NonNull Path path) {
        String fileName = path.getFileName().toString();
        String suffix = ".properties";
        if (!fileName.endsWith(suffix)) {
            throw new StoreException("Vault row path is not a properties file", null);
        }
        return new SecretId(
                UUID.fromString(fileName.substring(0, fileName.length() - suffix.length())));
    }

    private void requireSecretPathMatches(
            @NonNull SecretId pathSecretId,
            @NonNull SecretId recordSecretId,
            @NonNull String rowKind) {
        if (!pathSecretId.equals(recordSecretId)) {
            throw new StoreException(rowKind + " path does not match secret id", null);
        }
    }

    private void recoverVaultFiles(@NonNull VaultId vaultId) {
        listStoredSecretRecords(vaultId).stream()
                .filter(this::isHiddenByNewerTombstone)
                .forEach(record -> deleteSecretRecord(vaultId, record.metadata().id()));
        listStoredDeletedSecretRecords(vaultId).stream()
                .filter(this::isHiddenByNewerRecord)
                .forEach(record -> deleteDeletedSecretRecord(vaultId, record.secretId()));
    }

    private void recoverRotation() {
        Path journalPath = vaultDirectory.resolve(ROTATION_JOURNAL_FILE);
        if (!exists(journalPath)) return;
        Path backup = vaultDirectory.resolve(ROTATION_BACKUP_DIRECTORY);
        try {
            Properties journal = load(journalPath);
            if (!"COMMITTED".equals(journal.getProperty("state"))) {
                if (exists(backup.resolve(VAULT_FILE))) {
                    deleteIfExists(vaultDirectory.resolve(VAULT_FILE));
                    moveIfExists(backup.resolve(VAULT_FILE), vaultDirectory.resolve(VAULT_FILE));
                }
                if (exists(backup.resolve("secrets"))) {
                    deleteDirectory(secretsDirectory);
                    moveIfExists(backup.resolve("secrets"), secretsDirectory);
                }
            }
            deleteDirectory(vaultDirectory.resolve(ROTATION_STAGE_DIRECTORY));
            deleteDirectory(backup);
            deleteIfExistsDurably(journalPath);
        } catch (IOException e) {
            throw new StoreException("Could not recover vault key rotation", e);
        }
    }

    private void writeHeader(@NonNull VaultHeader header, @NonNull Path path) {
        Properties properties = new SortedProperties();
        properties.setProperty("vaultId", header.vaultId().value().toString());
        properties.setProperty("formatVersion", Integer.toString(header.formatVersion()));
        properties.setProperty("kdfAlgorithm", header.kdfAlgorithm());
        properties.setProperty("kdfSalt", b64(header.kdfSalt()));
        properties.setProperty("kdfIterations", Integer.toString(header.kdfIterations()));
        writeKdfParameters(properties, header.kdfParameters());
        properties.setProperty("vaultKeyId", header.vaultKeyId().value());
        properties.setProperty("wrappedVaultKey", b64(header.wrappedVaultKey()));
        properties.setProperty("createdAt", header.createdAt().toString());
        properties.setProperty("updatedAt", header.updatedAt().toString());
        store(properties, path);
    }

    private void writeRecord(@NonNull EncryptedSecretRecord record, @NonNull Path path) {
        Properties properties = new Properties();
        writeMetadata(properties, record.vaultId(), record.metadata());
        properties.setProperty("record.revision", Long.toString(record.revision()));
        EncryptedEnvelope envelope = record.payload();
        properties.setProperty("envelope.version", Integer.toString(envelope.version()));
        properties.setProperty("envelope.algorithm", envelope.algorithm());
        properties.setProperty("envelope.keyId", envelope.keyId().value());
        properties.setProperty("envelope.nonce", b64(envelope.nonce()));
        properties.setProperty("envelope.ciphertext", b64(envelope.ciphertext()));
        properties.setProperty("envelope.encryptedAt", envelope.encryptedAt().toString());
        store(properties, path);
    }

    private void moveIfExists(@NonNull Path source, @NonNull Path target) throws IOException {
        Path managedSource = requireManagedPath(source);
        Path managedTarget = requireManagedPath(target);
        if (Files.exists(managedSource)) {
            createDirectories(managedTarget.getParent());
            Files.move(
                    requireManagedPath(managedSource),
                    requireManagedPath(managedTarget),
                    StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private void deleteDirectory(@NonNull Path directory) throws IOException {
        Path managedDirectory = requireManagedPath(directory);
        if (!Files.exists(managedDirectory)) return;
        List<Path> managedPaths;
        try (var paths = Files.walk(requireManagedPath(managedDirectory))) {
            managedPaths = paths.map(this::requireManagedPath).toList();
        }
        for (Path path : managedPaths.stream().sorted(Comparator.reverseOrder()).toList()) {
            try {
                Files.deleteIfExists(requireManagedPath(path));
            } catch (IOException e) {
                throw new StoreException("Could not delete rotation files", e);
            }
        }
    }

    private static @NonNull Object processLock(@NonNull Path lockPath) {
        return PROCESS_LOCKS.computeIfAbsent(
                lockPath.toAbsolutePath().normalize(), path -> new Object());
    }

    private synchronized long currentRevision(@NonNull VaultId vaultId) {
        Properties properties = exists(revisionPath) ? load(revisionPath) : new Properties();
        @Nullable String value = properties.getProperty(revisionKey(vaultId));
        long indexedRevision = value == null ? 0L : Long.parseLong(value);
        return Math.max(
                indexedRevision, Math.max(maxSecretRevision(vaultId), maxDeletedRevision(vaultId)));
    }

    private synchronized void writeRevision(@NonNull VaultId vaultId, long revision) {
        Properties properties = exists(revisionPath) ? load(revisionPath) : new Properties();
        properties.setProperty(revisionKey(vaultId), Long.toString(revision));
        store(properties, revisionPath);
    }

    private long maxSecretRevision(@NonNull VaultId vaultId) {
        return listSecretRecords(vaultId).stream()
                .mapToLong(EncryptedSecretRecord::revision)
                .max()
                .orElse(0L);
    }

    private long maxDeletedRevision(@NonNull VaultId vaultId) {
        return listDeletedSecretRecords(vaultId).stream()
                .mapToLong(DeletedSecretRecord::revision)
                .max()
                .orElse(0L);
    }

    private @NonNull String revisionKey(@NonNull VaultId vaultId) {
        return "vault." + vaultId.value() + ".lastRevision";
    }

    private void store(@NonNull Properties properties, @NonNull Path path) {
        @Nullable Path temp = null;
        byte @Nullable [] serialized = null;
        try {
            try (WipeableByteArrayOutputStream output = new WipeableByteArrayOutputStream()) {
                properties.store(output, "Keystead v0.1");
                serialized = output.toByteArray();
            }
            if (serialized.length > SecurityLimits.MAX_STORED_PROPERTIES_BYTES) {
                throw new StoreException("Vault properties exceed the size limit", null);
            }
            Path managedPath = requireManagedPath(path);
            Path parent = requireManagedPath(managedPath.getParent());
            createDirectories(parent);
            temp =
                    Files.createTempFile(
                            requireManagedPath(parent),
                            managedPath.getFileName().toString() + ".",
                            ".tmp");
            temp = requireManagedPath(temp);
            // Write to a sibling temp file, then atomically move it into place so a crash
            // or IO error mid-write cannot truncate the existing vault/record file.
            Files.write(
                    requireManagedPath(temp),
                    serialized,
                    StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING);
            durability.force(requireManagedPath(temp), true);
            Files.move(
                    requireManagedPath(temp),
                    requireManagedPath(managedPath),
                    StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
            durability.force(requireManagedPath(parent), true);
        } catch (IOException e) {
            throw new StoreException("Could not store vault data", e);
        } finally {
            if (serialized != null) {
                Arrays.fill(serialized, (byte) 0);
            }
            try {
                if (temp != null) {
                    Files.deleteIfExists(requireManagedPath(temp));
                }
            } catch (IOException ignored) {
                // Best-effort cleanup of a leftover temp file.
            }
        }
    }

    private void deleteIfExistsDurably(@NonNull Path path) throws IOException {
        Path managedPath = requireManagedPath(path);
        if (Files.deleteIfExists(managedPath)) {
            durability.force(requireManagedPath(managedPath.getParent()), true);
        }
    }

    private @NonNull Properties load(@NonNull Path path) {
        byte @Nullable [] serialized = null;
        try (InputStream input = Files.newInputStream(requireManagedPath(path))) {
            serialized = input.readNBytes(SecurityLimits.MAX_STORED_PROPERTIES_BYTES + 1);
            if (serialized.length > SecurityLimits.MAX_STORED_PROPERTIES_BYTES) {
                throw new StoreException("Vault properties exceed the size limit", null);
            }
            Properties properties = new Properties();
            properties.load(new ByteArrayInputStream(serialized));
            return properties;
        } catch (IOException e) {
            throw new StoreException("Could not load vault data", e);
        } finally {
            if (serialized != null) {
                Arrays.fill(serialized, (byte) 0);
            }
        }
    }

    private boolean exists(@NonNull Path path) {
        return Files.exists(requireManagedPath(path));
    }

    private void createDirectories(@NonNull Path directory) throws IOException {
        Path managed = requireManagedPath(directory);
        // Files.createDirectories throws FileAlreadyExistsException on Windows when the leaf is a
        // symbolic link to a directory (it does not follow the link, so it cannot see that the
        // target already exists). A caller-selected vault root may legitimately be such a link, so
        // skip creation when the path is already a directory following links. This is a no-op on
        // POSIX and avoids rejecting a symlinked vault root on Windows.
        if (Files.isDirectory(managed)) {
            return;
        }
        Files.createDirectories(managed);
    }

    private void deleteIfExists(@NonNull Path path) throws IOException {
        Files.deleteIfExists(requireManagedPath(path));
    }

    private @NonNull Path requireManagedPath(@NonNull Path path) {
        Path target = Objects.requireNonNull(path, "path").toAbsolutePath().normalize();
        if (!target.startsWith(vaultDirectory)) {
            throw new StoreException("Vault path is outside the vault directory", null);
        }
        Path component = vaultDirectory;
        for (Path name : vaultDirectory.relativize(target)) {
            // Path.relativize yields a single empty-name element when target is the vault root
            // itself (vd.relativize(vd) has nameCount 1, not 0), and resolving it leaves
            // component at the caller-selected root. The root may legitimately be a symbolic
            // link because the caller chose it; only reject symbolic links below the root,
            // which would escape the managed tree.
            if (name.toString().isEmpty()) {
                continue;
            }
            component = component.resolve(name);
            if (Files.isSymbolicLink(component)) {
                throw new StoreException("Vault path contains a symbolic link", null);
            }
        }
        return target;
    }

    private @NonNull String required(@NonNull Properties properties, @NonNull String key) {
        @Nullable String value = properties.getProperty(key);
        if (value == null) {
            throw new StoreException("Vault data is missing required field: " + key, null);
        }
        return value;
    }

    private int intValue(@NonNull Properties properties, @NonNull String key) {
        return Integer.parseInt(required(properties, key));
    }

    private void writeKdfParameters(
            @NonNull Properties properties, @NonNull KdfParameters parameters) {
        parameters.parameters().entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(
                        entry ->
                                properties.setProperty(
                                        KDF_PARAMETER_PREFIX + entry.getKey(),
                                        Integer.toString(entry.getValue())));
    }

    private @NonNull KdfParameters readKdfParameters(@NonNull Properties properties) {
        String algorithm = required(properties, "kdfAlgorithm");
        String encodedSalt = required(properties, "kdfSalt");
        if (encodedSalt.length() > MAX_ENCODED_KDF_SALT_CHARACTERS) {
            throw new IllegalArgumentException("KDF salt exceeds the size limit");
        }
        byte @Nullable [] salt = null;
        try {
            salt = Base64.getDecoder().decode(encodedSalt);
            if (salt.length > SecurityLimits.MAX_KDF_SALT_BYTES) {
                throw new IllegalArgumentException("KDF salt exceeds the size limit");
            }
            Map<String, Integer> canonical = new LinkedHashMap<>();
            int canonicalCount = 0;
            Enumeration<Object> names = properties.keys();
            while (names.hasMoreElements()) {
                String name = (String) names.nextElement();
                if (!name.startsWith(KDF_PARAMETER_PREFIX)) {
                    continue;
                }
                canonicalCount++;
                if (canonicalCount > SecurityLimits.MAX_KDF_PARAMETER_ENTRIES) {
                    throw new IllegalArgumentException(
                            "KDF parameter count exceeds the size limit");
                }
                requireKdfParameterName(name);
                canonical.put(
                        name.substring(KDF_PARAMETER_PREFIX.length()),
                        Integer.parseInt(required(properties, name)));
            }
            return canonical.isEmpty()
                    ? KdfParameters.pbkdf2(algorithm, salt, intValue(properties, "kdfIterations"))
                    : new KdfParameters(algorithm, salt, canonical);
        } finally {
            if (salt != null) {
                Arrays.fill(salt, (byte) 0);
            }
        }
    }

    private void requireKdfParameterName(@NonNull String propertyName) {
        int parameterLength = propertyName.length() - KDF_PARAMETER_PREFIX.length();
        if (parameterLength <= 0
                || parameterLength > SecurityLimits.MAX_KDF_PARAMETER_NAME_CHARACTERS) {
            throw new IllegalArgumentException("KDF parameter name has an invalid length");
        }
        for (int index = KDF_PARAMETER_PREFIX.length(); index < propertyName.length(); index++) {
            char character = propertyName.charAt(index);
            if (character < 0x21 || character > 0x7e) {
                throw new IllegalArgumentException(
                        "KDF parameter name must contain printable ASCII");
            }
        }
    }

    private long longValue(@NonNull Properties properties, @NonNull String key) {
        return Long.parseLong(required(properties, key));
    }

    private byte @NonNull [] bytes(@NonNull Properties properties, @NonNull String key) {
        return base64Decoder.decode(key, required(properties, key));
    }

    private byte @NonNull [] boundedBytes(
            @NonNull Properties properties,
            @NonNull String key,
            int maximumBytes,
            @NonNull String label) {
        return boundedBytes(key, required(properties, key), maximumBytes, label);
    }

    private byte @NonNull [] boundedBytes(
            @NonNull String field,
            @NonNull String encoded,
            int maximumBytes,
            @NonNull String label) {
        requireDecodedLength(encoded, maximumBytes, label);
        byte[] decoded;
        try {
            decoded = base64Decoder.decode(field, encoded);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(label + " is invalid");
        }
        if (decoded.length > maximumBytes) {
            Arrays.fill(decoded, (byte) 0);
            throw new IllegalArgumentException(label + " exceeds the size limit");
        }
        return decoded;
    }

    private void requireDecodedLength(
            @NonNull String encoded, int maximumBytes, @NonNull String label) {
        int length = encoded.length();
        int padding = 0;
        while (padding < length && encoded.charAt(length - padding - 1) == '=') {
            padding++;
        }
        if (padding > 2 || (padding > 0 && length % 4 != 0)) {
            throw new IllegalArgumentException(label + " is invalid");
        }
        int dataLength = length - padding;
        int firstPadding = encoded.indexOf('=');
        if (firstPadding >= 0 && firstPadding < dataLength) {
            throw new IllegalArgumentException(label + " is invalid");
        }
        int remainder = dataLength % 4;
        if (remainder == 1
                || (padding == 1 && remainder != 3)
                || (padding == 2 && remainder != 2)) {
            throw new IllegalArgumentException(label + " is invalid");
        }
        long decodedLength =
                ((long) dataLength / 4) * 3 + (remainder == 2 ? 1 : remainder == 3 ? 2 : 0);
        if (decodedLength > maximumBytes) {
            throw new IllegalArgumentException(label + " exceeds the size limit");
        }
    }

    private @NonNull String text(@NonNull Properties properties, @NonNull String key) {
        return new String(bytes(properties, key), StandardCharsets.UTF_8);
    }

    private @NonNull Set<String> tags(@NonNull Properties properties) {
        String encoded = required(properties, "metadata.tags");
        return encodedSet(encoded);
    }

    private @NonNull Set<String> encodedSet(@NonNull String encoded) {
        if (encoded.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(encoded.split(","))
                .map(value -> new String(Base64.getDecoder().decode(value), StandardCharsets.UTF_8))
                .collect(Collectors.toUnmodifiableSet());
    }

    private @NonNull String encodedMap(@NonNull Map<String, String> values) {
        return values.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .map(entry -> b64(entry.getKey()) + ":" + b64(entry.getValue()))
                .collect(Collectors.joining(","));
    }

    private @NonNull Map<String, String> encodedMap(@NonNull String encoded) {
        if (encoded.isBlank()) {
            return Map.of();
        }
        return Arrays.stream(encoded.split(","))
                .map(value -> value.split(":", 2))
                .filter(parts -> parts.length == 2)
                .collect(
                        Collectors.toUnmodifiableMap(
                                parts ->
                                        new String(
                                                Base64.getDecoder().decode(parts[0]),
                                                StandardCharsets.UTF_8),
                                parts ->
                                        new String(
                                                Base64.getDecoder().decode(parts[1]),
                                                StandardCharsets.UTF_8)));
    }

    private void setNullableText(
            @NonNull Properties properties, @NonNull String key, @Nullable String value) {
        if (value != null) {
            properties.setProperty(key, b64(value));
        }
    }

    private @Nullable String optionalText(@NonNull Properties properties, @NonNull String key) {
        @Nullable String encoded = properties.getProperty(key);
        return encoded == null
                ? null
                : new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
    }

    private @NonNull String b64(@NonNull String value) {
        return b64(value.getBytes(StandardCharsets.UTF_8));
    }

    private @NonNull String b64(byte @NonNull [] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static void forcePath(@NonNull Path path, boolean metadata) throws IOException {
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
            channel.force(metadata);
        } catch (IOException e) {
            if (Files.isDirectory(path)) {
                return;
            }
            throw e;
        }
    }

    @FunctionalInterface
    interface Base64ValueDecoder {

        byte @NonNull [] decode(@NonNull String field, @NonNull String value);
    }
}

@FunctionalInterface
interface FileDurability {

    void force(@NonNull Path path, boolean metadata) throws IOException;
}
