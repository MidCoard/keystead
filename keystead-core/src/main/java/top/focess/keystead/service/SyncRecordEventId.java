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

/**
 * Computes the stable content hash used as an id for an encrypted sync-record event.
 *
 * <p>The KVE2 format hashes the record's identity fields (fingerprint, secret id, revision,
 * secret type, deletion flag) together with its {@code contentKey} — a vault-keyed HMAC of the
 * record plaintexts. Ciphertext fields are deliberately excluded: re-exporting an unchanged
 * record re-encrypts the profile with a fresh nonce, so hashing ciphertext would produce a new
 * id for the same logical record and break server-side dedup and client-side comparison.
 */
public final class SyncRecordEventId {

    private static final byte[] FORMAT_LABEL = {'K', 'V', 'E', '2'};

    private SyncRecordEventId() {}

    /**
     * Returns the unpadded base64url SHA-256 hash of the record identity fields and its keyed
     * content key.
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
                data.writeBoolean(record.deleted());
                write(data, record.contentKey());
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
