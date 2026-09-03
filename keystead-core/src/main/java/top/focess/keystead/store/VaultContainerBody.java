package top.focess.keystead.store;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
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
import top.focess.keystead.model.SecurityLimits;
import top.focess.keystead.model.VaultFingerprint;

/**
 * Binary codec for the decrypted body of the current single-file vault container.
 *
 * <p>The body holds the monotonic vault revision, the active encrypted secret records, and the
 * deleted-secret tombstones. It is serialized to a flat byte array, encrypted as one
 * authenticated-encryption envelope by {@link VaultFileFormat}, and integrity-protected by the
 * container AEAD tag (the header is the container AAD).
 *
 * <p>Each record's envelope is stored <em>without</em> its additional-authenticated data: the AAD is
 * recomputed on decode from the vault {@link VaultFingerprint}, the record metadata, and the record
 * revision via {@link SecretRecordAad#encode}. The fingerprint is read from the integrity-protected
 * header by {@link VaultFileFormat} and passed in, so a passphrase-less device open
 * recovers the same AAD without re-deriving the wrapping key.
 *
 * <p>Layout (big-endian, all lengths unsigned):
 * <pre>
 *   bodyVersion[1]       1
 *   vaultRevision        s64
 *   recordCount          s32
 *   records[recordCount]:
 *     secretId           s64 mostSigBits + s64 leastSigBits
 *     type               u16 len + UTF-8 (SecretType name)
 *     title              u16 len + UTF-8
 *     classification:
 *       category         u8 present + u16 len + UTF-8
 *       provider         u8 present + u16 len + UTF-8
 *       software         u8 present + u16 len + UTF-8
 *       account          u8 present + u16 len + UTF-8
 *       labelCount       u16
 *       labels[]         u16 len + UTF-8
 *     tagCount           u16
 *     tags[]             u16 len + UTF-8
 *     attributeCount     u16
 *     attributes[]       u16 len key + u16 len value
 *     createdAt          s64 epochSeconds + s32 nanos
 *     updatedAt          s64 epochSeconds + s32 nanos
 *     metadataRevision   s64
 *     envelope:
 *       version          u8
 *       algorithm        u16 len + UTF-8
 *       keyId            u16 len + UTF-8
 *       nonce            u8 len + bytes
 *       ciphertext       s32 len + bytes
 *       encryptedAt      s64 epochSeconds + s32 nanos
 *   tombstoneCount       s32
 *   tombstones[tombstoneCount]:
 *     secretId           s64 mostSigBits + s64 leastSigBits
 *     secretType         u16 len + UTF-8
 *     revision           s64
 *     deletedAt          s64 epochSeconds + s32 nanos
 * </pre>
 */
final class VaultContainerBody {

    /** Current container body format version. */
    static final int BODY_VERSION = 1;

    /** Upper bound on a single record or tombstone collection size, as a denial-of-service guard. */
    private static final int MAX_COLLECTION_SIZE = 1_000_000;

    private static final int MAX_NONCE_BYTES = 0xFF;
    private static final int MAX_STRING_BYTES = 0xFFFF;

    /** Result of decoding a container body. */
    record Decoded(
            long vaultRevision,
            @NonNull List<EncryptedSecretRecord> records,
            @NonNull List<DeletedSecretRecord> tombstones) {

        /** Validates and defensively copies the record components. */
        public Decoded {
            records = List.copyOf(records);
            tombstones = List.copyOf(tombstones);
        }
    }

    /** Serializes the vault revision, records, and tombstones to a flat byte array. */
    static byte @NonNull [] encode(
            long vaultRevision,
            @NonNull List<EncryptedSecretRecord> records,
            @NonNull List<DeletedSecretRecord> tombstones) {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        try (DataOutputStream data = new DataOutputStream(byteOut)) {
            data.writeByte(BODY_VERSION);
            data.writeLong(vaultRevision);
            writeCount(data, records.size());
            for (EncryptedSecretRecord record : records) {
                writeRecord(data, record);
            }
            writeCount(data, tombstones.size());
            for (DeletedSecretRecord tombstone : tombstones) {
                writeTombstone(data, tombstone);
            }
        } catch (IOException e) {
            throw new StoreException("Could not serialize vault container body", e);
        }
        return byteOut.toByteArray();
    }

    /** Parses a container body, recomputing each record envelope's AAD from the fingerprint. */
    static @NonNull Decoded decode(byte @NonNull [] body, @NonNull VaultFingerprint fingerprint) {
        ByteBuffer buffer = ByteBuffer.wrap(body);
        try {
            int version = buffer.get() & 0xFF;
            if (version != BODY_VERSION) {
                throw new StoreException("Unsupported vault body version: " + version, null);
            }
            long vaultRevision = buffer.getLong();
            int recordCount = readCount(buffer);
            List<EncryptedSecretRecord> records = new ArrayList<>(recordCount);
            for (int i = 0; i < recordCount; i++) {
                records.add(readRecord(buffer, fingerprint));
            }
            int tombstoneCount = readCount(buffer);
            List<DeletedSecretRecord> tombstones = new ArrayList<>(tombstoneCount);
            for (int i = 0; i < tombstoneCount; i++) {
                tombstones.add(readTombstone(buffer));
            }
            return new Decoded(vaultRevision, records, tombstones);
        } catch (BufferUnderflowException e) {
            throw new StoreException("Vault container body is truncated", e);
        }
    }

    private static void writeRecord(
            @NonNull DataOutputStream data, @NonNull EncryptedSecretRecord record)
            throws IOException {
        SecretMetadata metadata = record.metadata();
        writeUuid(data, metadata.secretId().value());
        writeShortString(data, metadata.secretType().name());
        writeShortString(data, metadata.title());
        writeClassification(data, metadata.classification());
        writeStringSet(data, metadata.tags());
        writeAttributes(data, metadata.profile().attributes());
        writeInstant(data, metadata.createdAt());
        writeInstant(data, metadata.updatedAt());
        data.writeLong(metadata.revision());
        writeEnvelope(data, record.payload());
    }

    private static void writeTombstone(
            @NonNull DataOutputStream data, @NonNull DeletedSecretRecord tombstone)
            throws IOException {
        writeUuid(data, tombstone.secretId().value());
        writeShortString(data, tombstone.secretType().name());
        data.writeLong(tombstone.revision());
        writeInstant(data, tombstone.deletedAt());
    }

    private static void writeClassification(
            @NonNull DataOutputStream data, @NonNull SecretClassification classification)
            throws IOException {
        writeNullableString(data, classification.category());
        writeNullableString(data, classification.provider());
        writeNullableString(data, classification.software());
        writeNullableString(data, classification.account());
        writeStringSet(data, classification.labels());
    }

    private static void writeEnvelope(
            @NonNull DataOutputStream data, @NonNull EncryptedEnvelope envelope)
            throws IOException {
        data.writeByte(envelope.version());
        writeShortString(data, envelope.algorithm());
        writeShortString(data, envelope.keyId().value());
        writeBytes(data, 1, envelope.nonce());
        writeBytes(data, 4, envelope.ciphertext());
        writeInstant(data, envelope.encryptedAt());
        // The AAD is recomputed on decode from the fingerprint, metadata, and revision.
    }

    private static void writeStringSet(
            @NonNull DataOutputStream data, java.util.@NonNull Set<String> values)
            throws IOException {
        if (values.size() > MAX_STRING_BYTES) {
            throw new IOException("String set exceeds the size limit");
        }
        data.writeShort(values.size());
        List<String> sorted = new ArrayList<>(values);
        java.util.Collections.sort(sorted);
        for (String value : sorted) {
            writeShortString(data, value);
        }
    }

    private static void writeAttributes(
            @NonNull DataOutputStream data, @NonNull Map<String, String> attributes)
            throws IOException {
        if (attributes.size() > MAX_STRING_BYTES) {
            throw new IOException("Attribute map exceeds the size limit");
        }
        data.writeShort(attributes.size());
        List<Map.Entry<String, String>> sorted = new ArrayList<>(attributes.entrySet());
        sorted.sort(Map.Entry.comparingByKey());
        for (Map.Entry<String, String> entry : sorted) {
            writeShortString(data, entry.getKey());
            writeShortString(data, entry.getValue());
        }
    }

    private static void writeUuid(@NonNull DataOutputStream data, @NonNull UUID uuid)
            throws IOException {
        data.writeLong(uuid.getMostSignificantBits());
        data.writeLong(uuid.getLeastSignificantBits());
    }

    private static void writeInstant(@NonNull DataOutputStream data, @NonNull Instant instant)
            throws IOException {
        data.writeLong(instant.getEpochSecond());
        data.writeInt(instant.getNano());
    }

    private static void writeNullableString(@NonNull DataOutputStream data, @Nullable String value)
            throws IOException {
        if (value == null) {
            data.writeByte(0);
        } else {
            data.writeByte(1);
            writeShortString(data, value);
        }
    }

    private static void writeShortString(@NonNull DataOutputStream data, @NonNull String value)
            throws IOException {
        byte[] utf = value.getBytes(StandardCharsets.UTF_8);
        if (utf.length > MAX_STRING_BYTES) {
            throw new IOException("String exceeds 65535 bytes");
        }
        data.writeShort(utf.length);
        data.write(utf);
    }

    private static void writeBytes(
            @NonNull DataOutputStream data, int lengthBytes, byte @NonNull [] bytes)
            throws IOException {
        long length = bytes.length;
        if (lengthBytes == 1) {
            if (length > MAX_NONCE_BYTES) {
                throw new IOException("Byte field exceeds 255 bytes");
            }
            data.writeByte((int) length);
        } else if (lengthBytes == 4) {
            if (length > SecurityLimits.MAX_ENVELOPE_CIPHERTEXT_BYTES) {
                throw new IOException("Byte field exceeds the ciphertext size limit");
            }
            data.writeInt((int) length);
        } else {
            throw new AssertionError("Unsupported length size: " + lengthBytes);
        }
        data.write(bytes);
    }

    private static void writeCount(@NonNull DataOutputStream data, int count) throws IOException {
        if (count < 0 || count > MAX_COLLECTION_SIZE) {
            throw new IOException("Collection size exceeds the limit: " + count);
        }
        data.writeInt(count);
    }

    private static @NonNull EncryptedSecretRecord readRecord(
            @NonNull ByteBuffer buffer, @NonNull VaultFingerprint fingerprint) {
        SecretId secretId = new SecretId(readUuid(buffer));
        SecretType type = SecretType.valueOf(readShortString(buffer));
        String title = readShortString(buffer);
        SecretClassification classification = readClassification(buffer);
        java.util.Set<String> tags = readStringSet(buffer);
        Map<String, String> attributes = readAttributes(buffer);
        Instant createdAt = readInstant(buffer);
        Instant updatedAt = readInstant(buffer);
        long metadataRevision = buffer.getLong();
        SecretMetadata metadata =
                new SecretMetadata(
                        secretId,
                        type,
                        new SecretProfile(title, classification, tags, attributes),
                        createdAt,
                        updatedAt,
                        metadataRevision);
        EncryptedEnvelope envelope = readEnvelope(buffer, fingerprint, metadata, metadataRevision);
        return new EncryptedSecretRecord(metadata, envelope, metadataRevision);
    }

    private static @NonNull DeletedSecretRecord readTombstone(@NonNull ByteBuffer buffer) {
        SecretId secretId = new SecretId(readUuid(buffer));
        SecretType secretType = SecretType.valueOf(readShortString(buffer));
        long revision = buffer.getLong();
        Instant deletedAt = readInstant(buffer);
        return new DeletedSecretRecord(secretId, secretType, revision, deletedAt);
    }

    private static @NonNull SecretClassification readClassification(@NonNull ByteBuffer buffer) {
        String category = readNullableString(buffer);
        String provider = readNullableString(buffer);
        String software = readNullableString(buffer);
        String account = readNullableString(buffer);
        java.util.Set<String> labels = readStringSet(buffer);
        return new SecretClassification(category, provider, software, account, labels);
    }

    private static @NonNull EncryptedEnvelope readEnvelope(
            @NonNull ByteBuffer buffer,
            @NonNull VaultFingerprint fingerprint,
            @NonNull SecretMetadata metadata,
            long revision) {
        int version = buffer.get() & 0xFF;
        if (version <= 0) {
            throw new StoreException("Invalid envelope version: " + version, null);
        }
        String algorithm = readShortString(buffer);
        KeyId keyId = new KeyId(readShortString(buffer));
        byte[] nonce = readBytes(buffer, 1, MAX_NONCE_BYTES);
        byte[] ciphertext = readBytes(buffer, 4, SecurityLimits.MAX_ENVELOPE_CIPHERTEXT_BYTES);
        Instant encryptedAt = readInstant(buffer);
        byte[] aad = SecretRecordAad.encode(fingerprint, metadata, revision);
        return new EncryptedEnvelope(
                version, algorithm, keyId, nonce, aad, ciphertext, encryptedAt);
    }

    private static java.util.@NonNull Set<String> readStringSet(@NonNull ByteBuffer buffer) {
        int count = buffer.getShort() & 0xFFFF;
        java.util.Set<String> values = new java.util.LinkedHashSet<>(count);
        for (int i = 0; i < count; i++) {
            values.add(readShortString(buffer));
        }
        return java.util.Collections.unmodifiableSet(values);
    }

    private static @NonNull Map<String, String> readAttributes(@NonNull ByteBuffer buffer) {
        int count = buffer.getShort() & 0xFFFF;
        Map<String, String> attributes = new LinkedHashMap<>(count);
        for (int i = 0; i < count; i++) {
            String key = readShortString(buffer);
            String value = readShortString(buffer);
            attributes.put(key, value);
        }
        return java.util.Collections.unmodifiableMap(attributes);
    }

    private static @NonNull UUID readUuid(@NonNull ByteBuffer buffer) {
        long mostSigBits = buffer.getLong();
        long leastSigBits = buffer.getLong();
        return new UUID(mostSigBits, leastSigBits);
    }

    private static @NonNull Instant readInstant(@NonNull ByteBuffer buffer) {
        long epochSecond = buffer.getLong();
        int nanos = buffer.getInt();
        return Instant.ofEpochSecond(epochSecond, nanos);
    }

    private static @Nullable String readNullableString(@NonNull ByteBuffer buffer) {
        int present = buffer.get() & 0xFF;
        if (present == 0) {
            return null;
        }
        return readShortString(buffer);
    }

    private static @NonNull String readShortString(@NonNull ByteBuffer buffer) {
        int length = buffer.getShort() & 0xFFFF;
        byte[] utf = new byte[length];
        buffer.get(utf);
        return new String(utf, StandardCharsets.UTF_8);
    }

    private static byte @NonNull [] readBytes(
            @NonNull ByteBuffer buffer, int lengthBytes, int maxLength) {
        long length;
        if (lengthBytes == 1) {
            length = buffer.get() & 0xFFL;
        } else if (lengthBytes == 4) {
            length = buffer.getInt() & 0xFFFFFFFFL;
        } else {
            throw new AssertionError("Unsupported length size: " + lengthBytes);
        }
        if (length > maxLength) {
            throw new StoreException("Vault body field exceeds the size limit", null);
        }
        byte[] bytes = new byte[(int) length];
        buffer.get(bytes);
        return bytes;
    }

    private static int readCount(@NonNull ByteBuffer buffer) {
        int count = buffer.getInt();
        if (count < 0 || count > MAX_COLLECTION_SIZE) {
            throw new StoreException("Invalid vault body collection size: " + count, null);
        }
        return count;
    }

    private VaultContainerBody() {}
}
