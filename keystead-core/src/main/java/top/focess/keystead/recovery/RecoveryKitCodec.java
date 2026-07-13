package top.focess.keystead.recovery;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import org.jspecify.annotations.NonNull;

/** Canonical printable encoding for {@link RecoveryKit}. */
public final class RecoveryKitCodec {

    private static final String PREFIX = "KEYSTEAD-RECOVERY-1";
    private static final int CHECKSUM_BYTES = 8;
    private static final int MAX_ENCODED_CHARACTERS = 512;

    private RecoveryKitCodec() {}

    public static @NonNull String encode(@NonNull RecoveryKit kit) {
        byte[] secret = kit.recoverySecret();
        try {
            String body =
                    PREFIX
                            + "."
                            + encode(kit.enrollmentId().getBytes(StandardCharsets.UTF_8))
                            + "."
                            + kit.generation()
                            + "."
                            + encode(secret);
            byte[] checksum = checksum(body);
            try {
                return body + "." + encode(checksum);
            } finally {
                Arrays.fill(checksum, (byte) 0);
            }
        } finally {
            Arrays.fill(secret, (byte) 0);
        }
    }

    public static @NonNull RecoveryKit decode(@NonNull String encoded) {
        try {
            if (encoded == null || encoded.isEmpty() || encoded.length() > MAX_ENCODED_CHARACTERS) {
                throw invalid();
            }
            String[] parts = encoded.split("\\.", -1);
            if (parts.length != 5 || !PREFIX.equals(parts[0])) {
                throw invalid();
            }
            byte[] enrollmentBytes = decodeCanonical(parts[1]);
            byte[] secret = decodeCanonical(parts[3]);
            byte[] suppliedChecksum = decodeCanonical(parts[4]);
            try {
                String enrollmentId = decodeUtf8(enrollmentBytes);
                long generation = parseGeneration(parts[2]);
                if (secret.length != RecoveryKit.SECRET_BYTES
                        || suppliedChecksum.length != CHECKSUM_BYTES) {
                    throw invalid();
                }
                String body = String.join(".", parts[0], parts[1], parts[2], parts[3]);
                byte[] expectedChecksum = checksum(body);
                try {
                    if (!MessageDigest.isEqual(expectedChecksum, suppliedChecksum)) {
                        throw invalid();
                    }
                    RecoveryKit kit =
                            new RecoveryKit(
                                    RecoveryKit.FORMAT_VERSION, enrollmentId, generation, secret);
                    if (!encoded.equals(encode(kit))) {
                        kit.close();
                        throw invalid();
                    }
                    return kit;
                } finally {
                    Arrays.fill(expectedChecksum, (byte) 0);
                }
            } finally {
                Arrays.fill(enrollmentBytes, (byte) 0);
                Arrays.fill(secret, (byte) 0);
                Arrays.fill(suppliedChecksum, (byte) 0);
            }
        } catch (IllegalArgumentException error) {
            if ("Recovery kit is invalid".equals(error.getMessage())) {
                throw error;
            }
            throw invalid();
        }
    }

    private static byte @NonNull [] decodeCanonical(@NonNull String value) {
        byte[] decoded = Base64.getUrlDecoder().decode(value);
        if (!encode(decoded).equals(value)) {
            Arrays.fill(decoded, (byte) 0);
            throw invalid();
        }
        return decoded;
    }

    private static @NonNull String decodeUtf8(byte @NonNull [] bytes) {
        try {
            return StandardCharsets.UTF_8
                    .newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes))
                    .toString();
        } catch (CharacterCodingException error) {
            throw invalid();
        }
    }

    private static long parseGeneration(@NonNull String encoded) {
        long generation = Long.parseLong(encoded);
        if (generation <= 0 || !Long.toString(generation).equals(encoded)) {
            throw invalid();
        }
        return generation;
    }

    private static byte @NonNull [] checksum(@NonNull String body) {
        try {
            return Arrays.copyOf(
                    MessageDigest.getInstance("SHA-256")
                            .digest(body.getBytes(StandardCharsets.UTF_8)),
                    CHECKSUM_BYTES);
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA-256 is unavailable", error);
        }
    }

    private static @NonNull String encode(byte @NonNull [] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private static @NonNull IllegalArgumentException invalid() {
        return new IllegalArgumentException("Recovery kit is invalid");
    }
}
