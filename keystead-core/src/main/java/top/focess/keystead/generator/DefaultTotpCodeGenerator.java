package top.focess.keystead.generator;

import java.io.ByteArrayOutputStream;
import java.time.Instant;
import java.util.Objects;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.memory.Wipe;

/**
 * Default {@link TotpCodeGenerator} implementing RFC 6238 with HMAC-SHA1.
 *
 * <p>The seed is a Base32 string (per the {@code otpauth} URI emitted by {@link MfaSecretGenerator})
 * and is decoded back to the raw key before HMAC. All intermediate buffers (decoded key, counter,
 * hash) are wiped in a {@code finally} block; the seed copy is wiped by {@link SecretBuffer}.
 */
public final class DefaultTotpCodeGenerator implements TotpCodeGenerator {

    /** Creates a default TOTP code generator. */
    public DefaultTotpCodeGenerator() {}

    private static final int[] POWERS_OF_TEN = {
        1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000,
    };
    private static final @NonNull String HMAC_ALGORITHM = "HmacSHA1";

    @Override
    public char @NonNull [] generate(
            int digits, int periodSeconds, @NonNull SecretBuffer seed, @NonNull Instant now) {
        Objects.requireNonNull(seed, "seed");
        Objects.requireNonNull(now, "now");
        if (digits < 6 || digits > 8) {
            throw new IllegalArgumentException("TOTP digits must be between 6 and 8: " + digits);
        }
        if (periodSeconds <= 0) {
            throw new IllegalArgumentException("TOTP period must be positive: " + periodSeconds);
        }
        char[] code = new char[digits];
        seed.copyBytes(
                seedBytes -> {
                    byte[] key = base32Decode(seedBytes);
                    byte[] message = counterBytes(now.getEpochSecond() / periodSeconds);
                    byte[] hash = null;
                    try {
                        hash = hmacSha1(key, message);
                        int offset = hash[hash.length - 1] & 0xf;
                        int truncated =
                                ((hash[offset] & 0x7f) << 24)
                                        | ((hash[offset + 1] & 0xff) << 16)
                                        | ((hash[offset + 2] & 0xff) << 8)
                                        | (hash[offset + 3] & 0xff);
                        int codeValue = truncated % POWERS_OF_TEN[digits];
                        for (int i = digits - 1; i >= 0; i--) {
                            code[i] = (char) ('0' + codeValue % 10);
                            codeValue /= 10;
                        }
                    } finally {
                        if (hash != null) {
                            Wipe.wipe(hash);
                        }
                        Wipe.wipe(message);
                        Wipe.wipe(key);
                    }
                });
        return code;
    }

    private static byte @NonNull [] hmacSha1(byte @NonNull [] key, byte @NonNull [] message) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
            return mac.doFinal(message);
        } catch (java.security.NoSuchAlgorithmException | java.security.InvalidKeyException e) {
            throw new IllegalStateException("HMAC-SHA1 is not available", e);
        }
    }

    private static byte @NonNull [] counterBytes(long counter) {
        byte[] bytes = new byte[8];
        for (int i = 7; i >= 0; i--) {
            bytes[i] = (byte) (counter & 0xff);
            counter >>>= 8;
        }
        return bytes;
    }

    private static byte @NonNull [] base32Decode(byte @NonNull [] input) {
        ByteArrayOutputStream output = new ByteArrayOutputStream(input.length * 5 / 8 + 1);
        int buffer = 0;
        int bitsLeft = 0;
        for (byte value : input) {
            int decoded = decodeChar(value);
            if (decoded < 0) {
                continue;
            }
            buffer = (buffer << 5) | decoded;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                bitsLeft -= 8;
                output.write((buffer >> bitsLeft) & 0xff);
            }
        }
        return output.toByteArray();
    }

    private static int decodeChar(byte value) {
        if (value >= 'A' && value <= 'Z') {
            return value - 'A';
        }
        if (value >= 'a' && value <= 'z') {
            return value - 'a';
        }
        if (value >= '2' && value <= '7') {
            return value - '2' + 26;
        }
        return -1;
    }
}
