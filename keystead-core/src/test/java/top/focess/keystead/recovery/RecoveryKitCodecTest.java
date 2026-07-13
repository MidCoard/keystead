package top.focess.keystead.recovery;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import org.junit.jupiter.api.Test;

class RecoveryKitCodecTest {

    @Test
    void roundTripsCanonicalPrintableKit() {
        byte[] secret = secret((byte) 7);
        try (RecoveryKit kit = new RecoveryKit(1, "enrollment-1", 3L, secret)) {
            String encoded = RecoveryKitCodec.encode(kit);
            assertTrue(encoded.startsWith("KEYSTEAD-RECOVERY-1."));
            try (RecoveryKit decoded = RecoveryKitCodec.decode(encoded)) {
                assertEquals(1, decoded.formatVersion());
                assertEquals("enrollment-1", decoded.enrollmentId());
                assertEquals(3L, decoded.generation());
                assertArrayEquals(secret, decoded.recoverySecret());
                assertEquals(encoded, RecoveryKitCodec.encode(decoded));
            }
        }
    }

    @Test
    void rejectsChangedChecksum() {
        String encoded;
        try (RecoveryKit kit = new RecoveryKit(1, "enrollment-1", 1L, secret((byte) 2))) {
            encoded = RecoveryKitCodec.encode(kit);
        }
        char replacement = encoded.endsWith("A") ? 'B' : 'A';
        String tampered = encoded.substring(0, encoded.length() - 1) + replacement;
        IllegalArgumentException error =
                assertThrows(
                        IllegalArgumentException.class, () -> RecoveryKitCodec.decode(tampered));
        assertEquals("Recovery kit is invalid", error.getMessage());
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
        assertThrows(IllegalArgumentException.class, () -> RecoveryKitCodec.decode(encoded));
    }

    private static byte[] secret(byte value) {
        byte[] secret = new byte[32];
        Arrays.fill(secret, value);
        return secret;
    }
}
