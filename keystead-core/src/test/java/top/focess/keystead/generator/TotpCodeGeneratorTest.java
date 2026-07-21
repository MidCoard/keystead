package top.focess.keystead.generator;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import top.focess.keystead.memory.SecretBuffer;

class TotpCodeGeneratorTest {

    private static final char[] BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();

    private final DefaultTotpCodeGenerator generator = new DefaultTotpCodeGenerator();

    @Test
    void matchesRfc6238VectorsAtEightDigits() {
        SecretBuffer seed = rfcSeed();
        try {
            MfaSecretPolicy policy =
                    new MfaSecretPolicy("Keystead", "alice@example.com", 20, 8, 30);
            assertEquals("94287082", code(policy, seed, 59L));
            assertEquals("07081804", code(policy, seed, 1111111109L));
            assertEquals("14050471", code(policy, seed, 1111111111L));
            assertEquals("89005924", code(policy, seed, 1234567890L));
            assertEquals("69279037", code(policy, seed, 2000000000L));
            assertEquals("65353130", code(policy, seed, 20000000000L));
        } finally {
            seed.close();
        }
    }

    @Test
    void matchesRfc4226HotpCountersAtSixDigits() {
        SecretBuffer seed = rfcSeed();
        try {
            MfaSecretPolicy policy =
                    new MfaSecretPolicy("Keystead", "alice@example.com", 20, 6, 30);
            // Counters 0, 1, 2 at a 30s period: t=29 -> counter 0, t=59 -> 1, t=89 -> 2.
            assertEquals("755224", code(policy, seed, 29L));
            assertEquals("287082", code(policy, seed, 59L));
            assertEquals("359152", code(policy, seed, 89L));
        } finally {
            seed.close();
        }
    }

    @Test
    void periodChangesTheCounter() {
        SecretBuffer seed = rfcSeed();
        try {
            MfaSecretPolicy thirty =
                    new MfaSecretPolicy("Keystead", "alice@example.com", 20, 8, 30);
            MfaSecretPolicy sixty = new MfaSecretPolicy("Keystead", "alice@example.com", 20, 8, 60);
            // t=59: a 30s period -> counter 1 (RFC 94287082); a 60s period -> counter 0
            // (different).
            assertEquals("94287082", code(thirty, seed, 59L));
            assertNotEquals(code(thirty, seed, 59L), code(sixty, seed, 59L));
        } finally {
            seed.close();
        }
    }

    @Test
    void sameInstantProducesSameCodeAndMatchesDigitsLength() {
        SecretBuffer seed = rfcSeed();
        try {
            MfaSecretPolicy policy =
                    new MfaSecretPolicy("Keystead", "alice@example.com", 20, 7, 30);
            char[] first = generator.generate(policy, seed, Instant.ofEpochSecond(1234567890L));
            char[] second = generator.generate(policy, seed, Instant.ofEpochSecond(1234567890L));
            assertEquals(7, first.length);
            assertArrayEquals(first, second);
            Arrays.fill(first, '\0');
            Arrays.fill(second, '\0');
        } finally {
            seed.close();
        }
    }

    @Test
    void rejectsNullArguments() {
        SecretBuffer seed = rfcSeed();
        try {
            MfaSecretPolicy policy = MfaSecretPolicy.totp("Keystead", "alice@example.com");
            assertThrows(
                    NullPointerException.class,
                    () -> generator.generate(null, seed, Instant.EPOCH));
            assertThrows(
                    NullPointerException.class,
                    () -> generator.generate(policy, null, Instant.EPOCH));
            assertThrows(NullPointerException.class, () -> generator.generate(policy, seed, null));
        } finally {
            seed.close();
        }
    }

    /** Builds a seed from the RFC 6238 reference secret (Base32-encoded "12345678901234567890"). */
    private static SecretBuffer rfcSeed() {
        byte[] secret = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
        char[] encoded = base32Encode(secret);
        Arrays.fill(secret, (byte) 0);
        SecretBuffer seed = SecretBuffer.fromChars(encoded);
        Arrays.fill(encoded, '\0');
        return seed;
    }

    private String code(MfaSecretPolicy policy, SecretBuffer seed, long epochSecond) {
        char[] chars = generator.generate(policy, seed, Instant.ofEpochSecond(epochSecond));
        String value = new String(chars);
        Arrays.fill(chars, '\0');
        return value;
    }

    /** Mirrors {@code DefaultMfaSecretGenerator}'s Base32 encoder for round-trip test seeds. */
    private static char[] base32Encode(byte[] secret) {
        char[] output = new char[(secret.length * 8 + 4) / 5];
        int outputIndex = 0;
        int buffer = 0;
        int bitsLeft = 0;
        for (byte value : secret) {
            buffer = (buffer << 8) | (value & 0xff);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                output[outputIndex++] = BASE32[(buffer >> (bitsLeft - 5)) & 0x1f];
                bitsLeft -= 5;
            }
        }
        if (bitsLeft > 0) {
            output[outputIndex] = BASE32[(buffer << (5 - bitsLeft)) & 0x1f];
        }
        return output;
    }
}
