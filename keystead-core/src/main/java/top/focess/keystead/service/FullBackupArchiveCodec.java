package top.focess.keystead.service;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.crypto.KdfParameters;
import top.focess.keystead.model.EncryptedEnvelope;
import top.focess.keystead.model.KeyId;
import top.focess.keystead.model.SecurityLimits;
import top.focess.keystead.model.VaultFingerprint;

final class FullBackupArchiveCodec {

    private static final byte[] MAGIC = "KSBACK01".getBytes(StandardCharsets.US_ASCII);
    private static final int MAX_STRING_BYTES = 1_024;
    private static final int MAX_WRAPPED_KEY_BYTES = 1_048_576;
    private static final int MAX_NONCE_BYTES = 64;
    private static final int MAX_CHUNKS = 64;

    private FullBackupArchiveCodec() {}

    static void write(@NonNull FullBackupArchive archive, @NonNull OutputStream output) {
        try {
            DataOutputStream data = new DataOutputStream(output);
            data.write(MAGIC);
            data.writeInt(archive.formatVersion());
            writeBytes(data, archive.fingerprint().value());
            writeString(data, archive.vaultKeyId().value());
            writeString(data, archive.backupKdf().algorithm());
            writeBytes(data, archive.backupKdf().salt());
            data.writeInt(archive.backupKdf().parameters().size());
            for (Map.Entry<String, Integer> parameter :
                    archive.backupKdf().parameters().entrySet()) {
                writeString(data, parameter.getKey());
                data.writeInt(parameter.getValue());
            }
            writeBytes(data, archive.wrappedVaultKey());
            writeBytes(data, archive.payloadDigest());
            writeString(data, archive.createdAt().toString());
            data.writeInt(archive.chunks().size());
            for (EncryptedEnvelope chunk : archive.chunks()) {
                data.writeInt(chunk.version());
                writeString(data, chunk.algorithm());
                writeString(data, chunk.keyId().value());
                writeBytes(data, chunk.nonce());
                writeBytes(data, chunk.aad());
                writeBytes(data, chunk.ciphertext());
                writeString(data, chunk.encryptedAt().toString());
            }
            data.flush();
        } catch (IOException error) {
            throw new ValidationException("Could not write full backup archive", error);
        }
    }

    static @NonNull FullBackupArchive read(@NonNull InputStream input) {
        try {
            DataInputStream data = new DataInputStream(input);
            byte[] magic = data.readNBytes(MAGIC.length);
            if (!java.util.Arrays.equals(MAGIC, magic)) {
                throw new ValidationException("Full backup magic is invalid");
            }
            int version = data.readInt();
            byte[] fingerprintBytes = readBytes(data, VaultFingerprint.BYTES);
            if (fingerprintBytes.length != VaultFingerprint.BYTES) {
                throw new ValidationException("Full backup fingerprint is invalid");
            }
            VaultFingerprint fingerprint = new VaultFingerprint(fingerprintBytes);
            KeyId vaultKeyId = new KeyId(readString(data));
            String kdfAlgorithm = readString(data);
            byte[] salt = readBytes(data, SecurityLimits.MAX_KDF_SALT_BYTES);
            int parameterCount = data.readInt();
            if (parameterCount < 0 || parameterCount > SecurityLimits.MAX_KDF_PARAMETER_ENTRIES) {
                throw new ValidationException("Full backup KDF parameter count is invalid");
            }
            Map<String, Integer> parameters = new LinkedHashMap<>();
            for (int index = 0; index < parameterCount; index++) {
                String name = readString(data);
                int value = data.readInt();
                if (parameters.putIfAbsent(name, value) != null) {
                    throw new ValidationException("Full backup KDF parameter is duplicated");
                }
            }
            KdfParameters kdf = new KdfParameters(kdfAlgorithm, salt, parameters);
            byte[] wrappedVaultKey = readBytes(data, MAX_WRAPPED_KEY_BYTES);
            byte[] digest = readBytes(data, 32);
            if (digest.length != 32) {
                throw new ValidationException("Full backup payload digest is invalid");
            }
            Instant createdAt = Instant.parse(readString(data));
            int chunkCount = data.readInt();
            if (chunkCount <= 0 || chunkCount > MAX_CHUNKS) {
                throw new ValidationException("Full backup chunk count is invalid");
            }
            List<EncryptedEnvelope> chunks = new ArrayList<>(chunkCount);
            for (int index = 0; index < chunkCount; index++) {
                int envelopeVersion = data.readInt();
                String algorithm = readString(data);
                KeyId envelopeKeyId = new KeyId(readString(data));
                byte[] nonce = readBytes(data, MAX_NONCE_BYTES);
                byte[] aad = readBytes(data, SecurityLimits.MAX_ENVELOPE_AAD_BYTES);
                byte[] ciphertext = readBytes(data, SecurityLimits.MAX_ENVELOPE_CIPHERTEXT_BYTES);
                Instant encryptedAt = Instant.parse(readString(data));
                chunks.add(
                        new EncryptedEnvelope(
                                envelopeVersion,
                                algorithm,
                                envelopeKeyId,
                                nonce,
                                aad,
                                ciphertext,
                                encryptedAt));
            }
            if (data.read() != -1) {
                throw new ValidationException("Full backup contains trailing data");
            }
            return new FullBackupArchive(
                    version,
                    fingerprint,
                    vaultKeyId,
                    kdf,
                    wrappedVaultKey,
                    digest,
                    chunks,
                    createdAt);
        } catch (EOFException error) {
            throw new ValidationException("Full backup archive is truncated", error);
        } catch (IOException | RuntimeException error) {
            if (error instanceof ValidationException validation) {
                throw validation;
            }
            throw new ValidationException("Could not read full backup archive", error);
        }
    }

    private static void writeString(@NonNull DataOutputStream data, @NonNull String value)
            throws IOException {
        writeBytes(data, value.getBytes(StandardCharsets.UTF_8));
    }

    private static @NonNull String readString(@NonNull DataInputStream data) throws IOException {
        return new String(readBytes(data, MAX_STRING_BYTES), StandardCharsets.UTF_8);
    }

    private static void writeBytes(@NonNull DataOutputStream data, byte @NonNull [] value)
            throws IOException {
        data.writeInt(value.length);
        data.write(value);
    }

    private static byte @NonNull [] readBytes(@NonNull DataInputStream data, int maximum)
            throws IOException {
        int length = data.readInt();
        if (length < 0 || length > maximum) {
            throw new ValidationException("Full backup field exceeds its size limit");
        }
        byte[] value = data.readNBytes(length);
        if (value.length != length) {
            throw new EOFException("Full backup field is truncated");
        }
        return value;
    }
}
