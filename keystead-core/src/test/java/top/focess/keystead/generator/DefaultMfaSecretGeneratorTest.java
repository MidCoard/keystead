package top.focess.keystead.generator;

import static org.junit.jupiter.api.Assertions.*;

import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class DefaultMfaSecretGeneratorTest {

    private final MfaSecretGenerator generator = new DefaultMfaSecretGenerator();

    @Test
    void generatesBase32TotpSeedAndOtpAuthUri() {
        try (MfaSecret secret =
                generator.generate(
                        new MfaSecretPolicy("Keystead", "alice@example.com", 20, 6, 30))) {
            String seed = copy(secret.seed());
            String uri = copy(secret.otpauthUri());

            assertEquals(32, seed.length());
            assertTrue(seed.matches("[A-Z2-7]+"));
            assertFalse(seed.contains("="));
            assertTrue(uri.startsWith("otpauth://totp/Keystead%3Aalice%40example.com?"));
            assertTrue(uri.contains("secret=" + seed));
            assertTrue(uri.contains("issuer=Keystead"));
            assertTrue(uri.contains("algorithm=SHA1"));
            assertTrue(uri.contains("digits=6"));
            assertTrue(uri.contains("period=30"));
        }
    }

    @Test
    void closesGeneratedSensitiveBuffers() {
        MfaSecret secret =
                generator.generate(new MfaSecretPolicy("Keystead", "alice@example.com", 20, 6, 30));
        secret.close();

        assertThrows(IllegalStateException.class, () -> secret.seed().copyChars(chars -> {}));
        assertThrows(IllegalStateException.class, () -> secret.otpauthUri().copyChars(chars -> {}));
    }

    @Test
    void encodesDeterministicRandomBytesAsRfc4648Base32() {
        byte[] randomBytes = new byte[20];
        for (int index = 0; index < randomBytes.length; index++) {
            randomBytes[index] = (byte) index;
        }
        MfaSecretGenerator deterministicGenerator =
                new DefaultMfaSecretGenerator(new FixedSecureRandom(randomBytes));

        try (MfaSecret secret =
                deterministicGenerator.generate(
                        new MfaSecretPolicy("Keystead", "alice@example.com", 20, 6, 30))) {
            secret.seed()
                    .copyChars(
                            seed ->
                                    assertArrayEquals(
                                            "AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQT".toCharArray(),
                                            seed));
        }
    }

    @Test
    void policyRejectsInvalidTotpParameters() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new MfaSecretPolicy("Keystead", "alice@example.com", 0, 6, 30));
        assertThrows(
                IllegalArgumentException.class,
                () -> new MfaSecretPolicy("Keystead", "alice@example.com", 20, 5, 30));
        assertThrows(
                IllegalArgumentException.class,
                () -> new MfaSecretPolicy("Keystead", "alice@example.com", 20, 6, 0));
    }

    private static String copy(top.focess.keystead.memory.SecretBuffer buffer) {
        AtomicReference<String> value = new AtomicReference<>("");
        buffer.copyChars(chars -> value.set(new String(chars)));
        return value.get();
    }

    private static final class FixedSecureRandom extends SecureRandom {

        private final byte[] values;

        private FixedSecureRandom(byte[] values) {
            this.values = values.clone();
        }

        @Override
        public void nextBytes(byte[] bytes) {
            assertEquals(values.length, bytes.length);
            System.arraycopy(values, 0, bytes, 0, values.length);
        }

        @Override
        public String toString() {
            return "FixedSecureRandom(<redacted>)";
        }
    }
}
