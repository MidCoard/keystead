package top.focess.keystead.service;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.model.DeletedSecretRecord;
import top.focess.keystead.model.EncryptedEnvelope;
import top.focess.keystead.model.EncryptedSecretRecord;
import top.focess.keystead.model.KeyId;
import top.focess.keystead.model.SecretClassification;
import top.focess.keystead.model.SecretId;
import top.focess.keystead.model.SecretMetadata;
import top.focess.keystead.model.SecretProfile;
import top.focess.keystead.model.SecretRecordAad;
import top.focess.keystead.model.SecretType;
import top.focess.keystead.model.VaultHeader;
import top.focess.keystead.model.VaultId;

final class BackupArchiveCodec {

    private static final String MANIFEST_ENTRY = "manifest.properties";
    private static final String VAULT_ENTRY = "vault.properties";
    private static final String RECORDS_PREFIX = "records/";
    private static final String DELETED_PREFIX = "deleted/";
    private static final String PROPERTIES_SUFFIX = ".properties";
    private static final String ENTRY_DIGEST_PREFIX = "entry.sha256.";

    private BackupArchiveCodec() {}

    static void write(@NonNull BackupArchive archive, @NonNull OutputStream output) {
        try (ZipOutputStream zip = new ZipOutputStream(output)) {
            List<BackupZipEntry> entries = new ArrayList<>();
            entries.add(backupZipEntry(VAULT_ENTRY, vaultProperties(archive.vaultHeader())));
            for (EncryptedSecretRecord record : archive.records()) {
                entries.add(
                        backupZipEntry(
                                RECORDS_PREFIX + record.metadata().id().value() + PROPERTIES_SUFFIX,
                                recordProperties(record)));
            }
            for (DeletedSecretRecord tombstone : archive.tombstones()) {
                entries.add(
                        backupZipEntry(
                                DELETED_PREFIX + tombstone.secretId().value() + PROPERTIES_SUFFIX,
                                deletedProperties(tombstone)));
            }
            putEntry(
                    zip,
                    MANIFEST_ENTRY,
                    propertiesBytes(manifestProperties(archive.manifest(), entries)));
            for (BackupZipEntry entry : entries) {
                putEntry(zip, entry.name(), entry.bytes());
            }
        } catch (IOException e) {
            throw new ValidationException("Could not write backup archive", e);
        }
    }

    static @NonNull BackupReadResult read(@NonNull InputStream input) {
        @Nullable BackupManifest manifest = null;
        @Nullable VaultHeader vaultHeader = null;
        List<EncryptedSecretRecord> records = new ArrayList<>();
        List<DeletedSecretRecord> tombstones = new ArrayList<>();
        int unsupported = 0;
        List<BackupZipEntry> entries = new ArrayList<>();
        try (ZipInputStream zip = new ZipInputStream(input)) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                entries.add(new BackupZipEntry(entry.getName(), zip.readAllBytes()));
            }
        } catch (IOException e) {
            throw new ValidationException("Could not read backup archive", e);
        }

        BackupZipEntry manifestEntry =
                findEntry(entries, MANIFEST_ENTRY)
                        .orElseThrow(
                                () ->
                                        new ValidationException(
                                                "Backup archive is missing manifest or vault"
                                                        + " header"));
        Map<String, String> entryDigests;
        try {
            Properties properties = toProperties(manifestEntry.bytes());
            manifest = readManifest(properties);
            entryDigests = entryDigests(properties);
        } catch (IOException | RuntimeException e) {
            throw new ValidationException("Backup archive is corrupt: " + MANIFEST_ENTRY, e);
        }

        for (BackupZipEntry entry : entries) {
            String name = entry.name();
            if (name.equals(MANIFEST_ENTRY)) {
                continue;
            }
            try {
                verifyEntryDigest(name, entry.bytes(), entryDigests);
                Properties properties = toProperties(entry.bytes());
                if (name.equals(VAULT_ENTRY)) {
                    vaultHeader = readVault(properties);
                } else if (name.startsWith(RECORDS_PREFIX) && name.endsWith(PROPERTIES_SUFFIX)) {
                    records.add(readRecord(properties));
                } else if (name.startsWith(DELETED_PREFIX) && name.endsWith(PROPERTIES_SUFFIX)) {
                    tombstones.add(readDeleted(properties));
                }
            } catch (IOException | RuntimeException e) {
                // Manifest and vault header are required; only record/tombstone entries may
                // be skipped so a single unsupported/corrupt record cannot brick the backup.
                if (name.startsWith(RECORDS_PREFIX) || name.startsWith(DELETED_PREFIX)) {
                    unsupported++;
                } else {
                    throw new ValidationException("Backup archive is corrupt: " + name, e);
                }
            }
        }
        if (manifest == null || vaultHeader == null) {
            throw new ValidationException("Backup archive is missing manifest or vault header");
        }
        return new BackupReadResult(
                new BackupArchive(manifest, vaultHeader, records, tombstones), unsupported);
    }

    private static @NonNull BackupZipEntry backupZipEntry(
            @NonNull String name, @NonNull Properties properties) throws IOException {
        return new BackupZipEntry(name, propertiesBytes(properties));
    }

    private static @NonNull Optional<BackupZipEntry> findEntry(
            @NonNull List<BackupZipEntry> entries, @NonNull String name) {
        return entries.stream().filter(entry -> entry.name().equals(name)).findFirst();
    }

    private static void putEntry(
            @NonNull ZipOutputStream zip, @NonNull String name, byte @NonNull [] bytes)
            throws IOException {
        zip.putNextEntry(new ZipEntry(name));
        zip.write(bytes);
        zip.closeEntry();
    }

    private static byte @NonNull [] propertiesBytes(@NonNull Properties properties)
            throws IOException {
        StringWriter writer = new StringWriter();
        properties.store(writer, null);
        return writer.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static @NonNull Properties toProperties(byte @NonNull [] bytes) throws IOException {
        Properties properties = new Properties();
        properties.load(new StringReader(new String(bytes, StandardCharsets.UTF_8)));
        return properties;
    }

    private static @NonNull Properties manifestProperties(
            @NonNull BackupManifest manifest, @NonNull List<BackupZipEntry> entries) {
        Properties properties = new Properties();
        properties.setProperty("formatVersion", Integer.toString(manifest.formatVersion()));
        properties.setProperty("vaultId", manifest.vaultId().value().toString());
        properties.setProperty("recordCount", Integer.toString(manifest.recordCount()));
        properties.setProperty("tombstoneCount", Integer.toString(manifest.tombstoneCount()));
        properties.setProperty("createdAt", manifest.createdAt().toString());
        for (BackupZipEntry entry : entries) {
            properties.setProperty(ENTRY_DIGEST_PREFIX + entry.name(), sha256(entry.bytes()));
        }
        return properties;
    }

    private static @NonNull BackupManifest readManifest(@NonNull Properties properties) {
        return new BackupManifest(
                parseInt(properties, "formatVersion"),
                new VaultId(UUID.fromString(required(properties, "vaultId"))),
                parseInt(properties, "recordCount"),
                parseInt(properties, "tombstoneCount"),
                Instant.parse(required(properties, "createdAt")));
    }

    private static @NonNull Map<String, String> entryDigests(@NonNull Properties properties) {
        return properties.stringPropertyNames().stream()
                .filter(name -> name.startsWith(ENTRY_DIGEST_PREFIX))
                .collect(
                        Collectors.toUnmodifiableMap(
                                name -> name.substring(ENTRY_DIGEST_PREFIX.length()),
                                properties::getProperty));
    }

    private static void verifyEntryDigest(
            @NonNull String name, byte @NonNull [] bytes, @NonNull Map<String, String> digests) {
        @Nullable String expected = digests.get(name);
        if (expected != null && !expected.equals(sha256(bytes))) {
            throw new ValidationException("Backup archive entry digest mismatch: " + name);
        }
    }

    private static @NonNull Properties vaultProperties(@NonNull VaultHeader header) {
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
        return properties;
    }

    private static @NonNull VaultHeader readVault(@NonNull Properties properties) {
        return new VaultHeader(
                new VaultId(UUID.fromString(required(properties, "vaultId"))),
                parseInt(properties, "formatVersion"),
                required(properties, "kdfAlgorithm"),
                bytes(properties, "kdfSalt"),
                parseInt(properties, "kdfIterations"),
                new KeyId(required(properties, "vaultKeyId")),
                bytes(properties, "wrappedVaultKey"),
                Instant.parse(required(properties, "createdAt")),
                Instant.parse(required(properties, "updatedAt")));
    }

    private static @NonNull Properties recordProperties(@NonNull EncryptedSecretRecord record) {
        Properties properties = new Properties();
        SecretMetadata metadata = record.metadata();
        properties.setProperty("vaultId", record.vaultId().value().toString());
        properties.setProperty("metadata.id", metadata.id().value().toString());
        properties.setProperty("metadata.type", metadata.type().name());
        properties.setProperty("metadata.title", b64(metadata.title()));
        writeClassification(properties, metadata.classification());
        properties.setProperty(
                "metadata.tags",
                metadata.tags().stream()
                        .sorted()
                        .map(BackupArchiveCodec::b64)
                        .collect(Collectors.joining(",")));
        properties.setProperty("metadata.attributes", encodedMap(metadata.profile().attributes()));
        properties.setProperty("metadata.createdAt", metadata.createdAt().toString());
        properties.setProperty("metadata.updatedAt", metadata.updatedAt().toString());
        properties.setProperty("metadata.revision", Long.toString(metadata.revision()));
        properties.setProperty("record.revision", Long.toString(record.revision()));
        EncryptedEnvelope envelope = record.payload();
        properties.setProperty("envelope.version", Integer.toString(envelope.version()));
        properties.setProperty("envelope.algorithm", envelope.algorithm());
        properties.setProperty("envelope.keyId", envelope.keyId().value());
        properties.setProperty("envelope.nonce", b64(envelope.nonce()));
        properties.setProperty("envelope.ciphertext", b64(envelope.ciphertext()));
        properties.setProperty("envelope.encryptedAt", envelope.encryptedAt().toString());
        return properties;
    }

    private static @NonNull EncryptedSecretRecord readRecord(@NonNull Properties properties) {
        VaultId vaultId = new VaultId(UUID.fromString(required(properties, "vaultId")));
        SecretMetadata metadata =
                new SecretMetadata(
                        new SecretId(UUID.fromString(required(properties, "metadata.id"))),
                        SecretType.valueOf(required(properties, "metadata.type")),
                        new SecretProfile(
                                text(properties, "metadata.title"),
                                readClassification(properties),
                                encodedSet(properties.getProperty("metadata.tags", "")),
                                encodedMap(properties.getProperty("metadata.attributes", ""))),
                        Instant.parse(required(properties, "metadata.createdAt")),
                        Instant.parse(required(properties, "metadata.updatedAt")),
                        parseLong(properties, "metadata.revision"));
        long recordRevision = parseLong(properties, "record.revision");
        EncryptedEnvelope envelope =
                new EncryptedEnvelope(
                        parseInt(properties, "envelope.version"),
                        required(properties, "envelope.algorithm"),
                        new KeyId(required(properties, "envelope.keyId")),
                        bytes(properties, "envelope.nonce"),
                        envelopeAad(properties, vaultId, metadata, recordRevision),
                        bytes(properties, "envelope.ciphertext"),
                        Instant.parse(required(properties, "envelope.encryptedAt")));
        return new EncryptedSecretRecord(vaultId, metadata, envelope, recordRevision);
    }

    private static byte @NonNull [] envelopeAad(
            @NonNull Properties properties,
            @NonNull VaultId vaultId,
            @NonNull SecretMetadata metadata,
            long recordRevision) {
        @Nullable String encoded = properties.getProperty("envelope.aad");
        if (encoded != null) {
            return Base64.getDecoder().decode(encoded);
        }
        return SecretRecordAad.encode(vaultId, metadata, recordRevision);
    }

    private static @NonNull Properties deletedProperties(@NonNull DeletedSecretRecord record) {
        Properties properties = new Properties();
        properties.setProperty("vaultId", record.vaultId().value().toString());
        properties.setProperty("secretId", record.secretId().value().toString());
        properties.setProperty("secretType", record.secretType().name());
        properties.setProperty("revision", Long.toString(record.revision()));
        properties.setProperty("deletedAt", record.deletedAt().toString());
        return properties;
    }

    private static @NonNull DeletedSecretRecord readDeleted(@NonNull Properties properties) {
        return new DeletedSecretRecord(
                new VaultId(UUID.fromString(required(properties, "vaultId"))),
                new SecretId(UUID.fromString(required(properties, "secretId"))),
                SecretType.valueOf(required(properties, "secretType")),
                parseLong(properties, "revision"),
                Instant.parse(required(properties, "deletedAt")));
    }

    private static void writeClassification(
            @NonNull Properties properties, @NonNull SecretClassification classification) {
        setNullable(properties, "classification.category", classification.category());
        setNullable(properties, "classification.provider", classification.provider());
        setNullable(properties, "classification.software", classification.software());
        setNullable(properties, "classification.account", classification.account());
        properties.setProperty("classification.labels", encodedSet(classification.labels()));
    }

    private static @NonNull SecretClassification readClassification(
            @NonNull Properties properties) {
        return new SecretClassification(
                optional(properties, "classification.category"),
                optional(properties, "classification.provider"),
                optional(properties, "classification.software"),
                optional(properties, "classification.account"),
                encodedSet(properties.getProperty("classification.labels", "")));
    }

    private static void setNullable(
            @NonNull Properties properties, @NonNull String key, @Nullable String value) {
        if (value != null) {
            properties.setProperty(key, b64(value));
        }
    }

    private static @Nullable String optional(@NonNull Properties properties, @NonNull String key) {
        @Nullable String encoded = properties.getProperty(key);
        return encoded == null ? null : text(encoded);
    }

    private static @NonNull Set<String> encodedSet(@NonNull String encoded) {
        if (encoded.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(encoded.split(","))
                .map(BackupArchiveCodec::text)
                .collect(Collectors.toUnmodifiableSet());
    }

    private static @NonNull String encodedSet(@NonNull Set<String> values) {
        return values.stream()
                .sorted()
                .map(BackupArchiveCodec::b64)
                .collect(Collectors.joining(","));
    }

    private static @NonNull Map<String, String> encodedMap(@NonNull String encoded) {
        if (encoded.isBlank()) {
            return Map.of();
        }
        return Arrays.stream(encoded.split(","))
                .map(value -> value.split(":", 2))
                .filter(parts -> parts.length == 2)
                .collect(
                        Collectors.toUnmodifiableMap(
                                parts -> text(parts[0]), parts -> text(parts[1])));
    }

    private static @NonNull String encodedMap(@NonNull Map<String, String> values) {
        return values.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .map(entry -> b64(entry.getKey()) + ":" + b64(entry.getValue()))
                .collect(Collectors.joining(","));
    }

    private static @NonNull String required(@NonNull Properties properties, @NonNull String key) {
        @Nullable String value = properties.getProperty(key);
        if (value == null) {
            throw new ValidationException("Backup entry is missing required field: " + key);
        }
        return value;
    }

    private static int parseInt(@NonNull Properties properties, @NonNull String key) {
        return Integer.parseInt(required(properties, key));
    }

    private static long parseLong(@NonNull Properties properties, @NonNull String key) {
        return Long.parseLong(required(properties, key));
    }

    private static byte @NonNull [] bytes(@NonNull Properties properties, @NonNull String key) {
        return Base64.getDecoder().decode(required(properties, key));
    }

    private static @NonNull String text(@NonNull Properties properties, @NonNull String key) {
        return text(required(properties, key));
    }

    private static @NonNull String text(@NonNull String encoded) {
        return new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
    }

    private static @NonNull String b64(@NonNull String value) {
        return b64(value.getBytes(StandardCharsets.UTF_8));
    }

    private static @NonNull String b64(byte @NonNull [] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static @NonNull String sha256(byte @NonNull [] bytes) {
        try {
            return b64(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 digest is unavailable", e);
        }
    }

    private record BackupZipEntry(@NonNull String name, byte @NonNull [] bytes) {

        private BackupZipEntry {
            Objects.requireNonNull(name, "name");
            Objects.requireNonNull(bytes, "bytes");
            bytes = Arrays.copyOf(bytes, bytes.length);
        }

        @Override
        public byte @NonNull [] bytes() {
            return Arrays.copyOf(bytes, bytes.length);
        }
    }
}
