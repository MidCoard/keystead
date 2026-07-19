package top.focess.keystead.recovery;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import org.junit.jupiter.api.Test;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.memory.SecretMemoryProvider;

class RecoveryKitCodecTest {

    @Test
    void roundTripsCanonicalPrintableKit() {
        byte[] secret = secret((byte) 7);
        try (RecoveryKit kit = new RecoveryKit(1, "enrollment-一", 3L, secret);
                SecretBuffer encoded = RecoveryKitCodec.encodeSecret(kit);
                RecoveryKit decoded = RecoveryKitCodec.decode(encoded)) {
            encoded.copyChars(
                    chars -> assertTrue(new String(chars).startsWith("KEYSTEAD-RECOVERY-1.")));
            assertEquals(1, decoded.formatVersion());
            assertEquals("enrollment-一", decoded.enrollmentId());
            assertEquals(3L, decoded.generation());
            assertArrayEquals(secret, decoded.recoverySecret());
        }
    }

    @Test
    void rejectsChangedChecksum() {
        char[] encodedChars;
        try (RecoveryKit kit = new RecoveryKit(1, "enrollment-1", 1L, secret((byte) 2));
                SecretBuffer encoded = RecoveryKitCodec.encodeSecret(kit)) {
            encodedChars = new char[encoded.length()];
            encoded.copyChars(chars -> System.arraycopy(chars, 0, encodedChars, 0, chars.length));
        }
        try {
            encodedChars[encodedChars.length - 1] =
                    encodedChars[encodedChars.length - 1] == 'A' ? 'B' : 'A';
            try (SecretBuffer tampered = SecretBuffer.fromChars(encodedChars)) {
                IllegalArgumentException error =
                        assertThrows(
                                IllegalArgumentException.class,
                                () -> RecoveryKitCodec.decode(tampered));
                assertEquals("Recovery kit is invalid", error.getMessage());
            }
        } finally {
            Arrays.fill(encodedChars, '\0');
        }
    }

    @Test
    void rejectsMalformedAndNonCanonicalKits() {
        assertInvalid("");
        assertInvalid("KEYSTEAD-RECOVERY-2.ZW5yb2xsbWVudC0x.1.AA.AA");
        assertInvalid("KEYSTEAD-RECOVERY-1.ZW5yb2xsbWVudC0x.0.AA.AA");
        assertInvalid("KEYSTEAD-RECOVERY-1.ZW5yb2xsbWVudC0x.1.AA==.AA");
        assertInvalid("KEYSTEAD-RECOVERY-1.ZW5yb2xsbWVudC0x.1.AA.AA.extra");
        assertInvalid("X".repeat(513));
    }

    @Test
    void doesNotExposeRecoverySecretInText() {
        byte[] secret = secret((byte) 11);
        try (RecoveryKit kit = new RecoveryKit(1, "enrollment-1", 1L, secret)) {
            assertEquals("RecoveryKit(<redacted>)", kit.toString());
            assertFalse(kit.toString().contains(Arrays.toString(secret)));
        }
    }

    private static void assertInvalid(String encoded) {
        char[] chars = encoded.toCharArray();
        try (SecretBuffer buffer = SecretBuffer.fromChars(chars, SecretMemoryProvider.heap())) {
            assertThrows(IllegalArgumentException.class, () -> RecoveryKitCodec.decode(buffer));
        } finally {
            Arrays.fill(chars, '\0');
        }
    }

    private static byte[] secret(byte value) {
        byte[] secret = new byte[32];
        Arrays.fill(secret, value);
        return secret;
    }
}
