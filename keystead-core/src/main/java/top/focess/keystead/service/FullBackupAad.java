package top.focess.keystead.service;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.crypto.KdfParameters;
import top.focess.keystead.model.KeyId;
import top.focess.keystead.model.VaultFingerprint;

final class FullBackupAad {

    private static final byte[] LABEL =
            "keystead-full-backup-v1".getBytes(StandardCharsets.US_ASCII);

    private FullBackupAad() {}

    static byte @NonNull [] encode(
            int formatVersion,
            @NonNull VaultFingerprint fingerprint,
            @NonNull KeyId vaultKeyId,
            @NonNull KdfParameters kdf,
            byte @NonNull [] wrappedVaultKey,
            byte @NonNull [] payloadDigest,
            @NonNull Instant createdAt,
            int chunkIndex,
            int chunkCount) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (DataOutputStream data = new DataOutputStream(bytes)) {
                data.writeInt(LABEL.length);
                data.write(LABEL);
                data.writeInt(formatVersion);
                writeBytes(data, fingerprint.value());
                writeString(data, vaultKeyId.value());
                writeString(data, kdf.algorithm());
                writeBytes(data, kdf.salt());
                data.writeInt(kdf.parameters().size());
                for (Map.Entry<String, Integer> parameter : kdf.parameters().entrySet()) {
                    writeString(data, parameter.getKey());
                    data.writeInt(parameter.getValue());
                }
                writeBytes(data, wrappedVaultKey);
                writeBytes(data, payloadDigest);
                writeString(data, createdAt.toString());
                data.writeInt(chunkIndex);
                data.writeInt(chunkCount);
            }
            return bytes.toByteArray();
        } catch (IOException error) {
            throw new ValidationException(
                    "Could not encode full backup authentication data", error);
        }
    }

    private static void writeString(@NonNull DataOutputStream data, @NonNull String value)
            throws IOException {
        writeBytes(data, value.getBytes(StandardCharsets.UTF_8));
    }

    private static void writeBytes(@NonNull DataOutputStream data, byte @NonNull [] value)
            throws IOException {
        data.writeInt(value.length);
        data.write(value);
    }
}
