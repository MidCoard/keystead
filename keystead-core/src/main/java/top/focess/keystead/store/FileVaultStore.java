package top.focess.keystead.store;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.model.*;

public final class FileVaultStore implements VaultStore {

    private static final String VAULT_FILE = "vault.properties";

    private final Path vaultDirectory;
    private final Path secretsDirectory;

    public FileVaultStore(@NonNull Path vaultDirectory) {
        this.vaultDirectory = Objects.requireNonNull(vaultDirectory, "vaultDirectory");
        this.secretsDirectory = vaultDirectory.resolve("secrets");
    }

    @Override
    public void saveVaultHeader(@NonNull VaultHeader header) {
        Objects.requireNonNull(header, "header");
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
        store(properties, vaultDirectory.resolve(VAULT_FILE));
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
    public void saveSecretRecord(@NonNull EncryptedSecretRecord record) {
        Objects.requireNonNull(record, "record");
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
    }

    @Override
    public @NonNull Optional<EncryptedSecretRecord> loadSecretRecord(
            @NonNull VaultId vaultId, @NonNull SecretId secretId) {
        Objects.requireNonNull(vaultId, "vaultId");
        Objects.requireNonNull(secretId, "secretId");
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
        return Optional.of(
                new EncryptedSecretRecord(
                        storedVaultId,
                        metadata,
                        envelope,
                        longValue(properties, "record.revision")));
    }

    @Override
    public @NonNull List<SecretMetadata> listMetadata(@NonNull VaultId vaultId) {
        Objects.requireNonNull(vaultId, "vaultId");
        if (!Files.exists(secretsDirectory)) {
            return List.of();
        }
        try (var stream = Files.list(secretsDirectory)) {
            return stream.filter(path -> path.getFileName().toString().endsWith(".properties"))
                    .map(this::load)
                    .filter(
                            properties ->
                                    vaultId.value()
                                            .toString()
                                            .equals(properties.getProperty("vaultId")))
                    .map(this::readMetadata)
                    .sorted(Comparator.comparing(metadata -> metadata.id().value()))
                    .toList();
        } catch (IOException e) {
            throw new StoreException("Could not list secret metadata", e);
        }
    }

    private void writeMetadata(
            @NonNull Properties properties,
            @NonNull VaultId vaultId,
            @NonNull SecretMetadata metadata) {
        properties.setProperty("vaultId", vaultId.value().toString());
        properties.setProperty("metadata.id", metadata.id().value().toString());
        properties.setProperty("metadata.type", metadata.type().name());
        properties.setProperty("metadata.title", b64(metadata.title()));
        properties.setProperty(
                "metadata.tags",
                metadata.tags().stream().sorted().map(this::b64).collect(Collectors.joining(",")));
        properties.setProperty("metadata.createdAt", metadata.createdAt().toString());
        properties.setProperty("metadata.updatedAt", metadata.updatedAt().toString());
        properties.setProperty("metadata.revision", Long.toString(metadata.revision()));
    }

    private @NonNull SecretMetadata readMetadata(@NonNull Properties properties) {
        return new SecretMetadata(
                new SecretId(UUID.fromString(required(properties, "metadata.id"))),
                SecretType.valueOf(required(properties, "metadata.type")),
                text(properties, "metadata.title"),
                tags(properties),
                Instant.parse(required(properties, "metadata.createdAt")),
                Instant.parse(required(properties, "metadata.updatedAt")),
                longValue(properties, "metadata.revision"));
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

    private @NonNull Path secretPath(@NonNull SecretId secretId) {
        return secretsDirectory.resolve(secretId.value() + ".properties");
    }

    private void store(@NonNull Properties properties, @NonNull Path path) {
        try {
            Files.createDirectories(path.getParent());
            try (OutputStream output = Files.newOutputStream(path)) {
                properties.store(output, "Keystead v0.1");
            }
        } catch (IOException e) {
            throw new StoreException("Could not store vault data", e);
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
        if (encoded.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(encoded.split(","))
                .map(value -> new String(Base64.getDecoder().decode(value), StandardCharsets.UTF_8))
                .collect(Collectors.toUnmodifiableSet());
    }

    private @NonNull String b64(@NonNull String value) {
        return b64(value.getBytes(StandardCharsets.UTF_8));
    }

    private @NonNull String b64(byte @NonNull [] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }
}
