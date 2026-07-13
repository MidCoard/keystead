package top.focess.keystead.recovery;

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

/** Strict binary encoding and human-comparable fingerprint for device recovery requests. */
public final class RecoveryDeviceRequestCodec {

    private static final byte[] MAGIC = {'K', 'R', 'R', '1'};
    private static final int MAX_ENCODED_BYTES = 256 * 1024;
    private static final int MAX_TEXT_BYTES = 64 * 1024;
    private static final int MAX_KEY_BYTES = 64 * 1024;

    private RecoveryDeviceRequestCodec() {}

    public static byte @NonNull [] encode(@NonNull RecoveryDeviceRequest request) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (DataOutputStream output = new DataOutputStream(bytes)) {
                output.write(MAGIC);
                output.writeInt(request.formatVersion());
                writeText(output, request.requestId());
                writeText(output, request.username());
                writeText(output, request.nonce());
                output.writeLong(request.expiresAt().getEpochSecond());
                writeText(output, request.deviceId());
                writeText(output, request.proofKeyAlgorithm());
                writeBytes(output, request.proofPublicKey());
                writeText(output, request.wrappingKeyAlgorithm());
                writeBytes(output, request.wrappingPublicKey());
            }
            byte[] encoded = bytes.toByteArray();
            if (encoded.length > MAX_ENCODED_BYTES) {
                Arrays.fill(encoded, (byte) 0);
                throw invalid();
            }
            return encoded;
        } catch (IOException error) {
            throw new IllegalStateException("Could not encode recovery device request", error);
        }
    }

    public static @NonNull RecoveryDeviceRequest decode(byte @NonNull [] encoded) {
        if (encoded.length == 0 || encoded.length > MAX_ENCODED_BYTES) {
            throw invalid();
        }
        byte[] inputBytes = Arrays.copyOf(encoded, encoded.length);
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(inputBytes))) {
            byte[] magic = input.readNBytes(MAGIC.length);
            if (!Arrays.equals(magic, MAGIC)) {
                throw invalid();
            }
            int version = input.readInt();
            String requestId = readText(input);
            String username = readText(input);
            String nonce = readText(input);
            Instant expiresAt = Instant.ofEpochSecond(input.readLong());
            String deviceId = readText(input);
            String proofAlgorithm = readText(input);
            byte[] proofKey = readBytes(input, MAX_KEY_BYTES);
            String wrappingAlgorithm = readText(input);
            byte[] wrappingKey = readBytes(input, MAX_KEY_BYTES);
            try {
                RecoveryDeviceRequest request =
                        new RecoveryDeviceRequest(
                                version,
                                requestId,
                                username,
                                nonce,
                                expiresAt,
                                deviceId,
                                proofAlgorithm,
                                proofKey,
                                wrappingAlgorithm,
                                wrappingKey);
                if (input.available() != 0 || !Arrays.equals(encoded, encode(request))) {
                    throw invalid();
                }
                return request;
            } finally {
                Arrays.fill(proofKey, (byte) 0);
                Arrays.fill(wrappingKey, (byte) 0);
            }
        } catch (IOException | RuntimeException error) {
            if (error instanceof IllegalArgumentException illegal
                    && "Recovery device request is invalid".equals(illegal.getMessage())) {
                throw illegal;
            }
            throw invalid();
        } finally {
            Arrays.fill(inputBytes, (byte) 0);
        }
    }

    public static @NonNull String fingerprint(@NonNull RecoveryDeviceRequest request) {
        byte[] encoded = encode(request);
        byte[] digest = digest(encoded);
        try {
            StringBuilder fingerprint = new StringBuilder(24);
            for (int index = 0; index < 10; index++) {
                if (index > 0 && index % 2 == 0) {
                    fingerprint.append('-');
                }
                fingerprint.append(String.format("%02X", digest[index] & 0xff));
            }
            return fingerprint.toString();
        } finally {
            Arrays.fill(encoded, (byte) 0);
            Arrays.fill(digest, (byte) 0);
        }
    }

    private static void writeText(@NonNull DataOutputStream output, @NonNull String value)
            throws IOException {
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        try {
            if (encoded.length == 0 || encoded.length > MAX_TEXT_BYTES) {
                throw invalid();
            }
            output.writeInt(encoded.length);
            output.write(encoded);
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    private static void writeBytes(@NonNull DataOutputStream output, byte @NonNull [] value)
            throws IOException {
        try {
            output.writeInt(value.length);
            output.write(value);
        } finally {
            Arrays.fill(value, (byte) 0);
        }
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
            Arrays.fill(encoded, (byte) 0);
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
            Arrays.fill(value, (byte) 0);
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
        return new IllegalArgumentException("Recovery device request is invalid");
    }
}
