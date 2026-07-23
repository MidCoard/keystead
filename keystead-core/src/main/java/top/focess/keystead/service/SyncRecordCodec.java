package top.focess.keystead.service;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.memory.Wipe;
import top.focess.keystead.model.EncryptedEnvelope;
import top.focess.keystead.model.KeyId;
import top.focess.keystead.model.SecretClassification;
import top.focess.keystead.model.SecretId;
import top.focess.keystead.model.SecretMetadata;
import top.focess.keystead.model.SecretProfile;
import top.focess.keystead.model.SecretType;
import top.focess.keystead.model.SecurityLimits;

final class SyncRecordCodec {

    private SyncRecordCodec() {}

    static @NonNull String envelopeWithoutAad(@NonNull EncryptedEnvelope envelope) {
        Objects.requireNonNull(envelope, "envelope");
        Properties properties = new Properties();
        properties.setProperty("version", Integer.toString(envelope.version()));
        properties.setProperty("algorithm", envelope.algorithm());
        properties.setProperty("keyId", envelope.keyId().value());
        properties.setProperty("nonce", b64(envelope.nonce()));
        properties.setProperty("ciphertext", b64(envelope.ciphertext()));
        properties.setProperty("encryptedAt", envelope.encryptedAt().toString());
        return properties(properties);
    }

    static byte @NonNull [] profileBytes(@NonNull SecretMetadata metadata) {
        Objects.requireNonNull(metadata, "metadata");
        Properties properties = new Properties();
        properties.setProperty("title", metadata.title());
        properties.setProperty("createdAt", metadata.createdAt().toString());
        properties.setProperty("updatedAt", metadata.updatedAt().toString());
        properties.setProperty("metadataRevision", Long.toString(metadata.revision()));
        writeClassification(properties, metadata.classification());
        properties.setProperty("tags", encodedSet(metadata.tags()));
        properties.setProperty("attributes", encodedMap(metadata.profile().attributes()));
        return properties(properties).getBytes(StandardCharsets.UTF_8);
    }

    static byte @NonNull [] profileAad(
            @NonNull String vaultId, @NonNull String secretId, long revision) {
        Objects.requireNonNull(vaultId, "vaultId");
        Objects.requireNonNull(secretId, "secretId");
        return "keystead-sync-profile-v1|%s|%s|%d"
                .formatted(vaultId, secretId, revision)
                .getBytes(StandardCharsets.UTF_8);
    }

    static @NonNull EncryptedEnvelope envelopeWithAad(
            @NonNull String encoded, byte @NonNull [] aad) {
        return envelopeWithAad(encoded, aad, (field, value) -> Base64.getDecoder().decode(value));
    }

    static @NonNull EncryptedEnvelope envelopeWithAad(
            @NonNull String encoded,
            byte @NonNull [] aad,
            @NonNull Base64ValueDecoder base64Decoder) {
        Objects.requireNonNull(encoded, "encoded");
        Objects.requireNonNull(aad, "aad");
        Objects.requireNonNull(base64Decoder, "base64Decoder");
        Properties properties = properties(encoded);
        return new EncryptedEnvelope(
                intValue(properties, "version"),
                required(properties, "algorithm"),
                new KeyId(required(properties, "keyId")),
                b64Bytes(properties, "nonce", base64Decoder),
                aad,
                boundedB64Bytes(
                        properties,
                        "ciphertext",
                        SecurityLimits.MAX_ENVELOPE_CIPHERTEXT_BYTES,
                        "Sync record ciphertext",
                        base64Decoder),
                Instant.parse(required(properties, "encryptedAt")));
    }

    static @NonNull SecretMetadata metadata(
            @NonNull EncryptedSyncRecord record, byte @NonNull [] profileBytes) {
        Objects.requireNonNull(record, "record");
        Objects.requireNonNull(profileBytes, "profileBytes");
        Properties properties = properties(new String(profileBytes, StandardCharsets.UTF_8));
        return new SecretMetadata(
                new SecretId(UUID.fromString(record.secretId())),
                SecretType.valueOf(record.secretType()),
                new SecretProfile(
                        required(properties, "title"),
                        readClassification(properties),
                        encodedSet(properties.getProperty("tags", "")),
                        encodedMap(properties.getProperty("attributes", ""))),
                Instant.parse(required(properties, "createdAt")),
                Instant.parse(required(properties, "updatedAt")),
                longValue(properties, "metadataRevision"));
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
            properties.setProperty(key, value);
        }
    }

    private static @NonNull String encodedSet(@NonNull Set<String> values) {
        return values.stream().sorted().map(SyncRecordCodec::b64).reduce("", SyncRecordCodec::join);
    }

    private static @NonNull Set<String> encodedSet(@NonNull String encoded) {
        if (encoded.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(encoded.split(","))
                .map(value -> new String(Base64.getDecoder().decode(value), StandardCharsets.UTF_8))
                .collect(Collectors.toUnmodifiableSet());
    }

    private static @NonNull String encodedMap(@NonNull Map<String, String> values) {
        return values.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .map(entry -> b64(entry.getKey()) + ":" + b64(entry.getValue()))
                .reduce("", SyncRecordCodec::join);
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
                                parts ->
                                        new String(
                                                Base64.getDecoder().decode(parts[0]),
                                                StandardCharsets.UTF_8),
                                parts ->
                                        new String(
                                                Base64.getDecoder().decode(parts[1]),
                                                StandardCharsets.UTF_8)));
    }

    private static @NonNull String join(@NonNull String left, @NonNull String right) {
        return left.isEmpty() ? right : left + "," + right;
    }

    private static @NonNull String properties(@NonNull Properties properties) {
        try {
            StringWriter writer = new StringWriter();
            properties.store(writer, "Keystead sync v1");
            return writer.toString();
        } catch (IOException e) {
            throw new ValidationException("Could not encode sync record");
        }
    }

    private static @NonNull Properties properties(@NonNull String encoded) {
        try {
            Properties properties = new Properties();
            properties.load(new StringReader(encoded));
            return properties;
        } catch (IOException e) {
            throw new ValidationException("Could not decode sync record");
        }
    }

    private static @NonNull String required(@NonNull Properties properties, @NonNull String key) {
        @Nullable String value = properties.getProperty(key);
        if (value == null) {
            throw new ValidationException("Sync record is missing required field: " + key);
        }
        return value;
    }

    private static @Nullable String optional(@NonNull Properties properties, @NonNull String key) {
        return properties.getProperty(key);
    }

    private static int intValue(@NonNull Properties properties, @NonNull String key) {
        return Integer.parseInt(required(properties, key));
    }

    private static long longValue(@NonNull Properties properties, @NonNull String key) {
        return Long.parseLong(required(properties, key));
    }

    private static byte @NonNull [] b64Bytes(@NonNull Properties properties, @NonNull String key) {
        return Base64.getDecoder().decode(required(properties, key));
    }

    private static byte @NonNull [] b64Bytes(
            @NonNull Properties properties,
            @NonNull String key,
            @NonNull Base64ValueDecoder base64Decoder) {
        return base64Decoder.decode(key, required(properties, key));
    }

    private static byte @NonNull [] boundedB64Bytes(
            @NonNull Properties properties,
            @NonNull String key,
            int maximumBytes,
            @NonNull String label,
            @NonNull Base64ValueDecoder base64Decoder) {
        String encoded = required(properties, key);
        requireDecodedLength(encoded, maximumBytes, label);
        byte[] decoded;
        try {
            decoded = base64Decoder.decode(key, encoded);
        } catch (IllegalArgumentException e) {
            throw new ValidationException(label + " is invalid");
        }
        if (decoded.length > maximumBytes) {
            Wipe.wipe(decoded);
            throw new ValidationException(label + " exceeds the size limit");
        }
        return decoded;
    }

    private static void requireDecodedLength(
            @NonNull String encoded, int maximumBytes, @NonNull String label) {
        int length = encoded.length();
        int padding = 0;
        while (padding < length && encoded.charAt(length - padding - 1) == '=') {
            padding++;
        }
        if (padding > 2 || (padding > 0 && length % 4 != 0)) {
            throw new ValidationException(label + " is invalid");
        }
        int dataLength = length - padding;
        if (encoded.indexOf('=') >= 0 && encoded.indexOf('=') < dataLength) {
            throw new ValidationException(label + " is invalid");
        }
        int remainder = dataLength % 4;
        if (remainder == 1
                || (padding == 1 && remainder != 3)
                || (padding == 2 && remainder != 2)) {
            throw new ValidationException(label + " is invalid");
        }
        long decodedLength =
                ((long) dataLength / 4) * 3 + (remainder == 2 ? 1 : remainder == 3 ? 2 : 0);
        if (decodedLength > maximumBytes) {
            throw new ValidationException(label + " exceeds the size limit");
        }
    }

    private static @NonNull String b64(@NonNull String value) {
        return b64(value.getBytes(StandardCharsets.UTF_8));
    }

    private static @NonNull String b64(byte @NonNull [] value) {
        return Base64.getEncoder().encodeToString(value);
    }

    @FunctionalInterface
    interface Base64ValueDecoder {

        byte @NonNull [] decode(@NonNull String field, @NonNull String value);
    }
}
