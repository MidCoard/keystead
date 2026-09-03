package top.focess.keystead.access;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Arrays;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.Wipe;

/** Strict encoding and public-key-bound comparison fingerprint for ephemeral access requests. */
public final class VaultAccessRequestCodec {

    private static final byte[] MAGIC = {'K', 'V', 'A', '2'};
    private static final int MAX_ENCODED_BYTES = 256 * 1024;
    private static final int MAX_TEXT_BYTES = 64 * 1024;
    private static final int MAX_KEY_BYTES = 64 * 1024;

    private VaultAccessRequestCodec() {}

    /** Encodes an access request into its canonical binary representation.
     *
     * @param request the request to encode
     * @return the canonical encoded bytes */
    public static byte @NonNull [] encode(@NonNull VaultAccessRequest request) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (DataOutputStream output = new DataOutputStream(bytes)) {
                output.write(MAGIC);
                output.writeInt(request.formatVersion());
                writeText(output, request.requestId());
                writeText(output, request.accountId());
                writeText(output, request.serverOrigin());
                output.writeLong(request.expiresAt().getEpochSecond());
                writeText(output, request.keyAlgorithm());
                writeBytes(output, request.exchangePublicKey());
            }
            byte[] encoded = bytes.toByteArray();
            if (encoded.length > MAX_ENCODED_BYTES) {
                Wipe.wipe(encoded);
                throw invalid();
            }
            return encoded;
        } catch (IOException error) {
            throw new IllegalStateException("Could not encode vault access request", error);
        }
    }

    /** Strictly decodes a canonical access request.
     *
     * @param encoded the encoded request bytes
     * @return the decoded request
     * @throws IllegalArgumentException if the input is malformed or not canonical */
    public static @NonNull VaultAccessRequest decode(byte @NonNull [] encoded) {
        if (encoded.length == 0 || encoded.length > MAX_ENCODED_BYTES) {
            throw invalid();
        }
        byte[] inputBytes = Arrays.copyOf(encoded, encoded.length);
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(inputBytes))) {
            if (!Arrays.equals(input.readNBytes(MAGIC.length), MAGIC)) {
                throw invalid();
            }
            int version = input.readInt();
            String requestId = readText(input);
            String accountId = readText(input);
            String serverOrigin = readText(input);
            Instant expiresAt = Instant.ofEpochSecond(input.readLong());
            String algorithm = readText(input);
            byte[] publicKey = readBytes(input, MAX_KEY_BYTES);
            try {
                VaultAccessRequest request =
                        new VaultAccessRequest(
                                version,
                                requestId,
                                accountId,
                                serverOrigin,
                                expiresAt,
                                algorithm,
                                publicKey);
                if (input.available() != 0 || !Arrays.equals(encoded, encode(request))) {
                    throw invalid();
                }
                return request;
            } finally {
                Wipe.wipe(publicKey);
            }
        } catch (IOException | RuntimeException error) {
            if (error instanceof IllegalArgumentException illegal
                    && "Vault access request is invalid".equals(illegal.getMessage())) {
                throw illegal;
            }
            throw invalid();
        } finally {
            Wipe.wipe(inputBytes);
        }
    }

    /** Returns the first 128 digest bits in an uppercase UUID-shaped comparison format.
     *
     * @param request the request to fingerprint
     * @return the comparison fingerprint */
    public static @NonNull String fingerprint(@NonNull VaultAccessRequest request) {
        byte[] encoded = encode(request);
        byte[] digest = digest(encoded);
        try {
            StringBuilder value = new StringBuilder(36);
            for (int index = 0; index < 16; index++) {
                if (index == 4 || index == 6 || index == 8 || index == 10) {
                    value.append('-');
                }
                value.append(String.format("%02X", digest[index] & 0xff));
            }
            return value.toString();
        } finally {
            Wipe.wipe(encoded);
            Wipe.wipe(digest);
        }
    }

    private static void writeText(@NonNull DataOutputStream output, @NonNull String value)
            throws IOException {
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        try {
            if (encoded.length == 0 || encoded.length > MAX_TEXT_BYTES) {
                throw invalid();
            }
            writeBytes(output, encoded);
        } finally {
            Wipe.wipe(encoded);
        }
    }

    private static void writeBytes(@NonNull DataOutputStream output, byte @NonNull [] value)
            throws IOException {
        output.writeInt(value.length);
        output.write(value);
    }

    private static @NonNull String readText(@NonNull DataInputStream input) throws IOException {
        byte[] encoded = readBytes(input, MAX_TEXT_BYTES);
        try {
            return StandardCharsets.UTF_8
                    .newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(encoded))
                    .toString();
        } catch (CharacterCodingException error) {
            throw invalid();
        } finally {
            Wipe.wipe(encoded);
        }
    }

    private static byte @NonNull [] readBytes(@NonNull DataInputStream input, int maximum)
            throws IOException {
        int length = input.readInt();
        if (length <= 0 || length > maximum || length > input.available()) {
            throw invalid();
        }
        byte[] value = input.readNBytes(length);
        if (value.length != length) {
            Wipe.wipe(value);
            throw invalid();
        }
        return value;
    }

    private static byte @NonNull [] digest(byte @NonNull [] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA-256 is unavailable", error);
        }
    }

    private static @NonNull IllegalArgumentException invalid() {
        return new IllegalArgumentException("Vault access request is invalid");
    }
}
