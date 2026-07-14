package top.focess.keystead.recovery;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class RecoveryContextCodecTest {

    @Test
    void version2SeparatesTuplesThatCollideInLegacyVersion1() {
        byte[] first = RecoveryContextCodec.version2("u", "v", "e", 1L, "k|generation:2|key:z");
        byte[] second = RecoveryContextCodec.version2("u", "v", "e|generation:1|key:k", 2L, "z");
        byte[] legacyFirst =
                RecoveryContextCodec.legacyVersion1("u", "v", "e", 1L, "k|generation:2|key:z");
        byte[] legacySecond =
                RecoveryContextCodec.legacyVersion1("u", "v", "e|generation:1|key:k", 2L, "z");
        try {
            assertFalse(Arrays.equals(first, second));
            assertArrayEquals(legacyFirst, legacySecond);
        } finally {
            Arrays.fill(first, (byte) 0);
            Arrays.fill(second, (byte) 0);
            Arrays.fill(legacyFirst, (byte) 0);
            Arrays.fill(legacySecond, (byte) 0);
        }
    }

    @Test
    void version2UsesMagicLengthPrefixedUtf8AndFixedWidthGeneration() {
        byte[] context = RecoveryContextCodec.version2("us\u00E9r", "v", "e", 7L, "key");
        try {
            ByteBuffer input = ByteBuffer.wrap(context);
            byte[] magic = new byte[4];
            input.get(magic);
            assertArrayEquals("KRC2".getBytes(StandardCharsets.US_ASCII), magic);
            assertEquals("us\u00E9r", readText(input));
            assertEquals("v", readText(input));
            assertEquals("e", readText(input));
            assertEquals(7L, input.getLong());
            assertEquals("key", readText(input));
            assertFalse(input.hasRemaining());
        } finally {
            Arrays.fill(context, (byte) 0);
        }
    }

    @Test
    void version2RejectsInvalidGenerationOversizedTextAndMalformedUtf8() {
        assertThrows(
                IllegalArgumentException.class,
                () -> RecoveryContextCodec.version2("u", "v", "e", 0L, "k"));
        assertThrows(
                IllegalArgumentException.class,
                () -> RecoveryContextCodec.version2("a".repeat(64 * 1024 + 1), "v", "e", 1L, "k"));
        assertThrows(
                IllegalArgumentException.class,
                () -> RecoveryContextCodec.version2("\uD800", "v", "e", 1L, "k"));
    }

    private static String readText(ByteBuffer input) {
        byte[] encoded = new byte[input.getInt()];
        input.get(encoded);
        return new String(encoded, StandardCharsets.UTF_8);
    }
}
