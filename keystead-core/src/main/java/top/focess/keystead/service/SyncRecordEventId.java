package top.focess.keystead.service;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

/** Computes the stable content hash used as an id for an encrypted sync-record event. */
public final class SyncRecordEventId {

    private static final byte[] FORMAT_LABEL = {'K', 'V', 'E', '1'};

    private SyncRecordEventId() {}

    /**
     * Returns the unpadded base64url SHA-256 hash of every authenticated transport field in {@code
     * record}.
     */
    public static @NonNull String of(@NonNull EncryptedSyncRecord record) {
        Objects.requireNonNull(record, "record");
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (DataOutputStream data = new DataOutputStream(bytes)) {
                data.write(FORMAT_LABEL);
                write(data, record.fingerprint());
                write(data, record.secretId());
                data.writeLong(record.revision());
                write(data, record.secretType());
                write(data, record.encryptedProfile());
                write(data, record.envelope());
                data.writeBoolean(record.deleted());
            }
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes.toByteArray());
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (IOException | NoSuchAlgorithmException error) {
            throw new IllegalStateException("Could not compute sync record event id", error);
        }
    }

    private static void write(@NonNull DataOutputStream data, @NonNull String value)
            throws IOException {
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        data.writeInt(encoded.length);
        data.write(encoded);
    }
}
