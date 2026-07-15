package top.focess.keystead.generator;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.SecureRandom;
import java.util.Date;
import org.junit.jupiter.api.Test;
import top.focess.keystead.testing.RecordingSecretMemoryProvider;

class GeneratorOwnershipTransferTest {

    @Test
    void mfaClosesBothSecretOwnersWhenAggregateFactoryThrowsAssertionError() {
        RecordingSecretMemoryProvider memory = new RecordingSecretMemoryProvider();
        DefaultMfaSecretGenerator generator =
                new DefaultMfaSecretGenerator(
                        new SecureRandom(),
                        memory,
                        (seed, uri) -> {
                            throw new AssertionError("injected MFA aggregate failure");
                        });

        assertThrows(
                AssertionError.class,
                () -> generator.generate(MfaSecretPolicy.totp("Keystead", "user@example.com")));

        assertTrue(memory.owner(0).isClosed());
        assertTrue(memory.owner(1).isClosed());
    }

    @Test
    void gpgClosesPrivateKeyOwnerWhenAggregateFactoryThrowsAssertionError() {
        RecordingSecretMemoryProvider memory = new RecordingSecretMemoryProvider();
        DefaultGpgKeyGenerator generator =
                new DefaultGpgKeyGenerator(
                        new SecureRandom(),
                        memory,
                        (publicKey, privateKey) -> {
                            throw new AssertionError("injected GPG aggregate failure");
                        });
        try (GpgKeyPolicy policy =
                new GpgKeyPolicy(
                        "Keystead User <user@example.com>",
                        "password".toCharArray(),
                        new Date(0),
                        3072)) {
            assertThrows(AssertionError.class, () -> generator.generate(policy));
        }

        assertTrue(memory.lastOwner().isClosed());
    }
}
