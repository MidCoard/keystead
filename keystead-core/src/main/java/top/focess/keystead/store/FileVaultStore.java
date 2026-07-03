package top.focess.keystead.store;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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
import top.focess.keystead.model.*;

public final class FileVaultStore implements VaultStore {

    private static final String VAULT_FILE = "vault.properties";
    private static final String REVISION_FILE = "revisions.properties";
    private static final String LOCK_FILE = ".keystead.lock";
    private static final ConcurrentMap<Path, Object> PROCESS_LOCKS = new ConcurrentHashMap<>();

    private final Path vaultDirectory;
    private final Path secretsDirectory;
    private final Path deletedDirectory;
    private final Path revisionPath;
    private final Path lockPath;
    private final FileDurability durability;

    public FileVaultStore(@NonNull Path vaultDirectory) {
        this(vaultDirectory, FileVaultStore::forcePath);
    }

    FileVaultStore(@NonNull Path vaultDirectory, @NonNull FileDurability durability) {
        this.vaultDirectory = Objects.requireNonNull(vaultDirectory, "vaultDirectory");
        this.durability = Objects.requireNonNull(durability, "durability");
        this.secretsDirectory = vaultDirectory.resolve("secrets");
        this.deletedDirectory = vaultDirectory.resolve("deleted");
        this.revisionPath = vaultDirectory.resolve(REVISION_FILE);
        this.lockPath = vaultDirectory.resolve(LOCK_FILE);
    }

    @Override
    public void saveVaultHeader(@NonNull VaultHeader header) {
        Objects.requireNonNull(header, "header");
        Path path = vaultDirectory.resolve(VAULT_FILE);
        if (Files.exists(path)) {
            VaultHeader existing = readHeader(load(path));
            if (!existing.vaultId().equals(header.vaultId())) {
                throw new StoreException("Vault directory already belongs to another vault", null);
            }
        }
        Properties properties = new Properties();
        properties.setProperty("vaultId", header.vaultId().value().toString());
        properties.setProperty("formatVersion", Integer.toString(header.formatVersion()));
        properties.setProperty("kdfAlgorithm", header.kdfAlgorithm());
        properties.setProperty("kdfSalt", b64(header.kdfSalt()));
        properties.setProperty("kdfIterations", Integer.toString(header.kdfIterations()));
        properties.setProperty("vaultKeyId", header.vaultKeyId().value());
        properties.setProperty("wrappedVaultKey", b64(header.wrappedVaultKey()));
        properties.setProperty("createdAt", header.createdAt().toString());
        properties.setProperty("updatedAt", header.updatedAt().toString());
        store(properties, path);
    }

    @Override
    public @NonNull Optional<VaultHeader> loadVaultHeader(@NonNull VaultId vaultId) {
        Objects.requireNonNull(vaultId, "vaultId");
        Path path = vaultDirectory.resolve(VAULT_FILE);
        if (!Files.exists(path)) {
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
                Files.createDirectories(vaultDirectory);
                try (FileChannel channel =
                                FileChannel.open(
                                        lockPath,
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
        properties.setProperty("envelope.aad", b64(envelope.aad()));
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
        return loadStoredSecretRecord(vaultId, secretId)
                .filter(record -> !isHiddenByNewerTombstone(record));
    }

    private @NonNull Optional<EncryptedSecretRecord> loadStoredSecretRecord(
            @NonNull VaultId vaultId, @NonNull SecretId secretId) {
        Path path = secretPath(secretId);
        if (!Files.exists(path)) {
            return Optional.empty();
        }
        Properties properties = load(path);
        VaultId storedVaultId = new VaultId(UUID.fromString(required(properties, "vaultId")));
        if (!storedVaultId.equals(vaultId)) {
            return Optional.empty();
        }
        SecretMetadata metadata = readMetadata(properties);
        EncryptedEnvelope envelope =
                new EncryptedEnvelope(
                        intValue(properties, "envelope.version"),
                        required(properties, "envelope.algorithm"),
                        new KeyId(required(properties, "envelope.keyId")),
                        bytes(properties, "envelope.nonce"),
                        bytes(properties, "envelope.aad"),
                        bytes(properties, "envelope.ciphertext"),
                        Instant.parse(required(properties, "envelope.encryptedAt")));
        EncryptedSecretRecord record =
                new EncryptedSecretRecord(
                        storedVaultId,
                        metadata,
                        envelope,
                        longValue(properties, "record.revision"));
        return Optional.of(record);
    }

    @Override
    public void deleteSecretRecord(@NonNull VaultId vaultId, @NonNull SecretId secretId) {
        Objects.requireNonNull(vaultId, "vaultId");
        Objects.requireNonNull(secretId, "secretId");
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
        return loadStoredDeletedSecretRecord(vaultId, secretId)
                .filter(record -> !isHiddenByNewerRecord(record));
    }

    private @NonNull Optional<DeletedSecretRecord> loadStoredDeletedSecretRecord(
            @NonNull VaultId vaultId, @NonNull SecretId secretId) {
        Path path = deletedPath(secretId);
        if (!Files.exists(path)) {
            return Optional.empty();
        }
        DeletedSecretRecord record = readDeletedRecord(load(path));
        if (!record.vaultId().equals(vaultId)) {
            return Optional.empty();
        }
        return Optional.of(record);
    }

    @Override
    public void deleteDeletedSecretRecord(@NonNull VaultId vaultId, @NonNull SecretId secretId) {
        Objects.requireNonNull(vaultId, "vaultId");
        Objects.requireNonNull(secretId, "secretId");
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
        return listStoredSecretRecords(vaultId).stream()
                .filter(record -> !isHiddenByNewerTombstone(record))
                .sorted(Comparator.comparing(record -> record.metadata().id().value()))
                .toList();
    }

    private @NonNull List<EncryptedSecretRecord> listStoredSecretRecords(@NonNull VaultId vaultId) {
        if (!Files.exists(secretsDirectory)) {
            return List.of();
        }
        try (var stream = Files.list(secretsDirectory)) {
            return stream.filter(path -> path.getFileName().toString().endsWith(".properties"))
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
            return Optional.of(readRecord(properties));
        } catch (StoreException | IllegalArgumentException e) {
            // A single corrupt/truncated record must not brick the whole vault listing.
            return Optional.empty();
        }
    }

    @Override
    public @NonNull List<DeletedSecretRecord> listDeletedSecretRecords(@NonNull VaultId vaultId) {
        Objects.requireNonNull(vaultId, "vaultId");
        return listStoredDeletedSecretRecords(vaultId).stream()
                .filter(record -> !isHiddenByNewerRecord(record))
                .sorted(Comparator.comparing(record -> record.secretId().value()))
                .toList();
    }

    private @NonNull List<DeletedSecretRecord> listStoredDeletedSecretRecords(
            @NonNull VaultId vaultId) {
        if (!Files.exists(deletedDirectory)) {
            return List.of();
        }
        try (var stream = Files.list(deletedDirectory)) {
            return stream.filter(path -> path.getFileName().toString().endsWith(".properties"))
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
            return Optional.of(readDeletedRecord(properties));
        } catch (StoreException | IllegalArgumentException e) {
            // A single corrupt tombstone must not brick the whole vault listing.
            return Optional.empty();
        }
    }

    private @NonNull EncryptedSecretRecord readRecord(@NonNull Properties properties) {
        VaultId storedVaultId = new VaultId(UUID.fromString(required(properties, "vaultId")));
        SecretMetadata metadata = readMetadata(properties);
        EncryptedEnvelope envelope =
                new EncryptedEnvelope(
                        intValue(properties, "envelope.version"),
                        required(properties, "envelope.algorithm"),
                        new KeyId(required(properties, "envelope.keyId")),
                        bytes(properties, "envelope.nonce"),
                        bytes(properties, "envelope.aad"),
                        bytes(properties, "envelope.ciphertext"),
                        Instant.parse(required(properties, "envelope.encryptedAt")));
        EncryptedSecretRecord record =
                new EncryptedSecretRecord(
                        storedVaultId,
                        metadata,
                        envelope,
                        longValue(properties, "record.revision"));
        return record;
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
                required(properties, "kdfAlgorithm"),
                bytes(properties, "kdfSalt"),
                intValue(properties, "kdfIterations"),
                new KeyId(required(properties, "vaultKeyId")),
                bytes(properties, "wrappedVaultKey"),
                Instant.parse(required(properties, "createdAt")),
                Instant.parse(required(properties, "updatedAt")));
    }

    private void requireVaultDirectoryIdentity(@NonNull VaultId vaultId) {
        Path path = vaultDirectory.resolve(VAULT_FILE);
        if (!Files.exists(path)) {
            return;
        }
        VaultHeader header = readHeader(load(path));
        if (!header.vaultId().equals(vaultId)) {
            throw new StoreException("Vault directory already belongs to another vault", null);
        }
    }

    private @NonNull Path secretPath(@NonNull SecretId secretId) {
        return secretsDirectory.resolve(secretId.value() + ".properties");
    }

    private @NonNull Path deletedPath(@NonNull SecretId secretId) {
        return deletedDirectory.resolve(secretId.value() + ".properties");
    }

    private void recoverVaultFiles(@NonNull VaultId vaultId) {
        listStoredSecretRecords(vaultId).stream()
                .filter(this::isHiddenByNewerTombstone)
                .forEach(record -> deleteSecretRecord(vaultId, record.metadata().id()));
        listStoredDeletedSecretRecords(vaultId).stream()
                .filter(this::isHiddenByNewerRecord)
                .forEach(record -> deleteDeletedSecretRecord(vaultId, record.secretId()));
    }

    private static @NonNull Object processLock(@NonNull Path lockPath) {
        return PROCESS_LOCKS.computeIfAbsent(
                lockPath.toAbsolutePath().normalize(), path -> new Object());
    }

    private synchronized long currentRevision(@NonNull VaultId vaultId) {
        Properties properties = Files.exists(revisionPath) ? load(revisionPath) : new Properties();
        @Nullable String value = properties.getProperty(revisionKey(vaultId));
        long indexedRevision = value == null ? 0L : Long.parseLong(value);
        return Math.max(
                indexedRevision, Math.max(maxSecretRevision(vaultId), maxDeletedRevision(vaultId)));
    }

    private synchronized void writeRevision(@NonNull VaultId vaultId, long revision) {
        Properties properties = Files.exists(revisionPath) ? load(revisionPath) : new Properties();
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
        try {
            Files.createDirectories(path.getParent());
            temp =
                    Files.createTempFile(
                            path.getParent(), path.getFileName().toString() + ".", ".tmp");
            // Write to a sibling temp file, then atomically move it into place so a crash
            // or IO error mid-write cannot truncate the existing vault/record file.
            try (OutputStream output =
                    Files.newOutputStream(
                            temp, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
                properties.store(output, "Keystead v0.1");
            }
            durability.force(temp, true);
            Files.move(
                    temp,
                    path,
                    StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
            durability.force(path.getParent(), true);
        } catch (IOException e) {
            throw new StoreException("Could not store vault data", e);
        } finally {
            try {
                if (temp != null) {
                    Files.deleteIfExists(temp);
                }
            } catch (IOException ignored) {
                // Best-effort cleanup of a leftover temp file.
            }
        }
    }

    private void deleteIfExistsDurably(@NonNull Path path) throws IOException {
        if (Files.deleteIfExists(path)) {
            durability.force(path.getParent(), true);
        }
    }

    private @NonNull Properties load(@NonNull Path path) {
        Properties properties = new Properties();
        try (InputStream input = Files.newInputStream(path)) {
            properties.load(input);
            return properties;
        } catch (IOException e) {
            throw new StoreException("Could not load vault data", e);
        }
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

    private long longValue(@NonNull Properties properties, @NonNull String key) {
        return Long.parseLong(required(properties, key));
    }

    private byte @NonNull [] bytes(@NonNull Properties properties, @NonNull String key) {
        return Base64.getDecoder().decode(required(properties, key));
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
}

@FunctionalInterface
interface FileDurability {

    void force(@NonNull Path path, boolean metadata) throws IOException;
}
