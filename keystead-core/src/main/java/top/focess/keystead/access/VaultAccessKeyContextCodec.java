package top.focess.keystead.access;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.Wipe;

/** Builds the authenticated context used when an approving session wraps a vault DEK. */
public final class VaultAccessKeyContextCodec {

    private static final byte[] MAGIC = {'K', 'V', 'A', 'C'};
    private static final int FORMAT_VERSION = 1;

    private VaultAccessKeyContextCodec() {}

    /**
     * Encodes the immutable request and the exact vault key generation into a deterministic
     * wrapping context.
     *
     * @param canonicalRequest canonical bytes issued by the server for this access request
     * @param vaultFingerprint fingerprint of the personal vault being transferred
     * @param vaultKeyId identifier of the DEK generation being transferred
     * @return a fresh context byte array
     */
    public static byte @NonNull [] encode(
            byte @NonNull [] canonicalRequest,
            @NonNull String vaultFingerprint,
            @NonNull String vaultKeyId) {
        Objects.requireNonNull(canonicalRequest, "canonicalRequest");
        Objects.requireNonNull(vaultFingerprint, "vaultFingerprint");
        Objects.requireNonNull(vaultKeyId, "vaultKeyId");
        if (canonicalRequest.length == 0 || vaultFingerprint.isBlank() || vaultKeyId.isBlank()) {
            throw new IllegalArgumentException("Vault access key context is invalid");
        }

        byte[] fingerprintBytes = vaultFingerprint.getBytes(StandardCharsets.UTF_8);
        byte[] keyIdBytes = vaultKeyId.getBytes(StandardCharsets.UTF_8);
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (DataOutputStream output = new DataOutputStream(bytes)) {
                output.write(MAGIC);
                output.writeInt(FORMAT_VERSION);
                writeBytes(output, canonicalRequest);
                writeBytes(output, fingerprintBytes);
                writeBytes(output, keyIdBytes);
            }
            return bytes.toByteArray();
        } catch (IOException error) {
            throw new IllegalStateException("Could not encode vault access key context", error);
        } finally {
            Wipe.wipe(fingerprintBytes);
            Wipe.wipe(keyIdBytes);
        }
    }

    private static void writeBytes(@NonNull DataOutputStream output, byte @NonNull [] value)
            throws IOException {
        output.writeInt(value.length);
        output.write(value);
    }
}
