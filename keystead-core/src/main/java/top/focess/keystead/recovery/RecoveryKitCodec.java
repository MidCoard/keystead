package top.focess.keystead.recovery;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.memory.SecretBuffer;

/** Canonical printable encoding for {@link RecoveryKit}. */
public final class RecoveryKitCodec {

    private static final byte[] PREFIX =
            new byte[] {
                'K', 'E', 'Y', 'S', 'T', 'E', 'A', 'D', '-', 'R', 'E', 'C', 'O', 'V', 'E', 'R', 'Y',
                '-', '1'
            };
    private static final int CHECKSUM_BYTES = 8;
    private static final int MAX_ENCODED_CHARACTERS = 512;
    private static final Base64.Encoder BASE64_ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder BASE64_DECODER = Base64.getUrlDecoder();

    private RecoveryKitCodec() {}

    /**
     * Encodes a recovery kit into owned mutable secret memory.
     *
     * @param kit recovery authority to encode
     * @return encoded recovery authority; the caller must close it
     */
    public static @NonNull SecretBuffer encodeSecret(@NonNull RecoveryKit kit) {
        Objects.requireNonNull(kit, "kit");
        byte[] enrollmentBytes = null;
        byte[] encodedEnrollment = null;
        byte[] generationBytes = null;
        byte[] secret = null;
        byte[] encodedSecret = null;
        byte[] body = null;
        byte[] checksum = null;
        byte[] encodedChecksum = null;
        byte[] encoded = null;
        try {
            enrollmentBytes = kit.enrollmentId().getBytes(StandardCharsets.UTF_8);
            encodedEnrollment = BASE64_ENCODER.encode(enrollmentBytes);
            generationBytes = Long.toString(kit.generation()).getBytes(StandardCharsets.US_ASCII);
            secret = kit.recoverySecret();
            encodedSecret = BASE64_ENCODER.encode(secret);

            body = join(PREFIX, encodedEnrollment, generationBytes, encodedSecret);
            checksum = checksum(body);
            encodedChecksum = BASE64_ENCODER.encode(checksum);
            encoded = appendChecksum(body, encodedChecksum);
            return SecretBuffer.fromUtf8(encoded);
        } finally {
            wipe(enrollmentBytes);
            wipe(encodedEnrollment);
            wipe(generationBytes);
            wipe(secret);
            wipe(encodedSecret);
            wipe(body);
            wipe(checksum);
            wipe(encodedChecksum);
            wipe(encoded);
        }
    }

    /**
     * Compatibility encoder whose returned secret {@link String} remains visible in heap dumps.
     * Prefer {@link #encodeSecret(RecoveryKit)} for new code.
     *
     * @param kit recovery authority to encode
     * @return the canonical printable encoding of the kit
     * @deprecated the returned {@link String} keeps the secret on the heap until garbage
     *     collection; use {@link #encodeSecret(RecoveryKit)} so the encoding lives in wipeable
     *     secret memory.
     */
    @Deprecated(forRemoval = false)
    public static @NonNull String encode(@NonNull RecoveryKit kit) {
        String[] encodedText = new String[1];
        try (SecretBuffer encoded = encodeSecret(kit)) {
            encoded.copyChars(chars -> encodedText[0] = new String(chars));
        }
        return Objects.requireNonNull(encodedText[0], "encoded recovery kit");
    }

    /**
     * Decodes a recovery kit without constructing a secret-bearing full-text {@link String}.
     *
     * @param encoded the canonical printable encoding held in secret memory
     * @return the decoded recovery kit; the caller must close it
     * @throws IllegalArgumentException if the encoding is malformed or the checksum does not match
     */
    public static @NonNull RecoveryKit decode(@NonNull SecretBuffer encoded) {
        Objects.requireNonNull(encoded, "encoded");
        RecoveryKit[] decoded = new RecoveryKit[1];
        try {
            encoded.copyBytes(bytes -> decoded[0] = decodeBytes(bytes));
            return Objects.requireNonNull(decoded[0], "decoded recovery kit");
        } catch (IllegalArgumentException error) {
            if (isInvalid(error)) {
                throw error;
            }
            throw invalid();
        }
    }

    /**
     * Compatibility decoder for an already heap-visible secret {@link String}. Prefer {@link
     * #decode(SecretBuffer)} for new code.
     *
     * @param encoded the canonical printable encoding
     * @return the decoded recovery kit; the caller must close it
     * @throws IllegalArgumentException if the encoding is malformed or the checksum does not match
     * @deprecated the {@link String} parameter keeps the secret on the heap until garbage
     *     collection; use {@link #decode(SecretBuffer)} so the encoding stays in wipeable secret
     *     memory.
     */
    @Deprecated(forRemoval = false)
    public static @NonNull RecoveryKit decode(@NonNull String encoded) {
        if (encoded == null || encoded.isEmpty() || encoded.length() > MAX_ENCODED_CHARACTERS) {
            throw invalid();
        }
        char[] characters = new char[encoded.length()];
        try {
            encoded.getChars(0, encoded.length(), characters, 0);
            try (SecretBuffer secretEncoded = SecretBuffer.fromChars(characters)) {
                return decode(secretEncoded);
            }
        } catch (IllegalArgumentException error) {
            if (isInvalid(error)) {
                throw error;
            }
            throw invalid();
        } finally {
            Arrays.fill(characters, '\0');
        }
    }

    private static @NonNull RecoveryKit decodeBytes(byte @NonNull [] encoded) {
        if (encoded.length == 0 || encoded.length > MAX_ENCODED_CHARACTERS) {
            throw invalid();
        }
        int firstDot = -1;
        int secondDot = -1;
        int thirdDot = -1;
        int fourthDot = -1;
        for (int index = 0; index < encoded.length; index++) {
            if (encoded[index] != '.') {
                continue;
            }
            if (firstDot < 0) {
                firstDot = index;
            } else if (secondDot < 0) {
                secondDot = index;
            } else if (thirdDot < 0) {
                thirdDot = index;
            } else if (fourthDot < 0) {
                fourthDot = index;
            } else {
                throw invalid();
            }
        }
        if (firstDot != PREFIX.length
                || secondDot <= firstDot + 1
                || thirdDot <= secondDot + 1
                || fourthDot <= thirdDot + 1
                || fourthDot >= encoded.length - 1
                || !matchesPrefix(encoded)) {
            throw invalid();
        }

        byte[] encodedEnrollment = null;
        byte[] generationBytes = null;
        byte[] encodedSecret = null;
        byte[] encodedChecksum = null;
        byte[] enrollmentBytes = null;
        byte[] secret = null;
        byte[] suppliedChecksum = null;
        byte[] body = null;
        byte[] expectedChecksum = null;
        try {
            encodedEnrollment = Arrays.copyOfRange(encoded, firstDot + 1, secondDot);
            generationBytes = Arrays.copyOfRange(encoded, secondDot + 1, thirdDot);
            encodedSecret = Arrays.copyOfRange(encoded, thirdDot + 1, fourthDot);
            encodedChecksum = Arrays.copyOfRange(encoded, fourthDot + 1, encoded.length);

            enrollmentBytes = decodeCanonical(encodedEnrollment);
            secret = decodeCanonical(encodedSecret);
            suppliedChecksum = decodeCanonical(encodedChecksum);
            if (secret.length != RecoveryKit.SECRET_BYTES
                    || suppliedChecksum.length != CHECKSUM_BYTES) {
                throw invalid();
            }
            String enrollmentId = decodeUtf8(enrollmentBytes);
            long generation = parseGeneration(generationBytes);
            body = Arrays.copyOf(encoded, fourthDot);
            expectedChecksum = checksum(body);
            if (!MessageDigest.isEqual(expectedChecksum, suppliedChecksum)) {
                throw invalid();
            }
            return new RecoveryKit(RecoveryKit.FORMAT_VERSION, enrollmentId, generation, secret);
        } finally {
            wipe(encodedEnrollment);
            wipe(generationBytes);
            wipe(encodedSecret);
            wipe(encodedChecksum);
            wipe(enrollmentBytes);
            wipe(secret);
            wipe(suppliedChecksum);
            wipe(body);
            wipe(expectedChecksum);
        }
    }

    private static boolean matchesPrefix(byte @NonNull [] encoded) {
        for (int index = 0; index < PREFIX.length; index++) {
            if (encoded[index] != PREFIX[index]) {
                return false;
            }
        }
        return true;
    }

    private static byte @NonNull [] decodeCanonical(byte @NonNull [] value) {
        byte[] decoded = null;
        byte[] canonical = null;
        boolean success = false;
        try {
            decoded = BASE64_DECODER.decode(value);
            canonical = BASE64_ENCODER.encode(decoded);
            if (!MessageDigest.isEqual(value, canonical)) {
                throw invalid();
            }
            success = true;
            return decoded;
        } catch (IllegalArgumentException error) {
            if (isInvalid(error)) {
                throw error;
            }
            throw invalid();
        } finally {
            if (!success) {
                wipe(decoded);
            }
            wipe(canonical);
        }
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

    private static long parseGeneration(byte @NonNull [] encoded) {
        for (byte value : encoded) {
            if (value < '0' || value > '9') {
                throw invalid();
            }
        }
        String generationText = new String(encoded, StandardCharsets.US_ASCII);
        try {
            long generation = Long.parseLong(generationText);
            if (generation <= 0 || !Long.toString(generation).equals(generationText)) {
                throw invalid();
            }
            return generation;
        } catch (NumberFormatException error) {
            throw invalid();
        }
    }

    private static byte @NonNull [] join(
            byte @NonNull [] prefix,
            byte @NonNull [] enrollment,
            byte @NonNull [] generation,
            byte @NonNull [] secret) {
        byte[] body =
                new byte
                        [Math.addExact(
                                Math.addExact(
                                        Math.addExact(prefix.length, enrollment.length),
                                        Math.addExact(generation.length, secret.length)),
                                3)];
        int offset = append(body, 0, prefix);
        body[offset++] = '.';
        offset = append(body, offset, enrollment);
        body[offset++] = '.';
        offset = append(body, offset, generation);
        body[offset++] = '.';
        append(body, offset, secret);
        return body;
    }

    private static byte @NonNull [] appendChecksum(
            byte @NonNull [] body, byte @NonNull [] checksum) {
        byte[] encoded = new byte[Math.addExact(Math.addExact(body.length, checksum.length), 1)];
        int offset = append(encoded, 0, body);
        encoded[offset++] = '.';
        append(encoded, offset, checksum);
        return encoded;
    }

    private static int append(byte @NonNull [] target, int offset, byte @NonNull [] value) {
        System.arraycopy(value, 0, target, offset, value.length);
        return offset + value.length;
    }

    private static byte @NonNull [] checksum(byte @NonNull [] body) {
        byte[] digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256").digest(body);
            return Arrays.copyOf(digest, CHECKSUM_BYTES);
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA-256 is unavailable", error);
        } finally {
            wipe(digest);
        }
    }

    private static void wipe(byte @Nullable [] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }

    private static boolean isInvalid(@NonNull IllegalArgumentException error) {
        return "Recovery kit is invalid".equals(error.getMessage());
    }

    private static @NonNull IllegalArgumentException invalid() {
        return new IllegalArgumentException("Recovery kit is invalid");
    }
}
