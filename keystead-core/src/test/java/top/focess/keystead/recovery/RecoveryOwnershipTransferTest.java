package top.focess.keystead.recovery;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import top.focess.keystead.crypto.DefaultCryptoService;

class RecoveryOwnershipTransferTest {

    @Test
    void enrollmentClosesKitWhenAggregateFactoryThrowsAssertionError() {
        AtomicReference<RecoveryKit> captured = new AtomicReference<>();
        DefaultRecoveryCryptoService service =
                new DefaultRecoveryCryptoService(
                        new SecureRandom(),
                        (kit, credential, publicKey, encryptedPrivateKey) -> {
                            captured.set(kit);
                            throw new AssertionError("injected enrollment aggregate failure");
                        });

        assertThrows(AssertionError.class, () -> service.enroll("enrollment", 1));

        assertTrue(captured.get().isClosed());
    }

    @Test
    void exceptionalSecondCopyWipesFirstCopyAndClosesTransferredKit() {
        byte[] copiedCredential = new byte[32];
        Arrays.fill(copiedCredential, (byte) 7);
        RecoveryKit kit = kit();
        RecoveryPublicKey publicKey =
                new RecoveryPublicKey(
                        "enrollment", 1, DefaultCryptoService.DEVICE_KEY_ALGORITHM, new byte[] {1});

        assertThrows(
                AssertionError.class,
                () ->
                        new RecoveryEnrollmentMaterial(
                                kit,
                                new byte[32],
                                publicKey,
                                new byte[] {2},
                                new RecoveryEnrollmentMaterial.SecretArrayCopier() {
                                    private int calls;

                                    @Override
                                    public byte[] copy(byte[] value) {
                                        if (calls++ == 0) {
                                            return copiedCredential;
                                        }
                                        throw new AssertionError("injected second copy failure");
                                    }
                                }));

        assertArrayEquals(new byte[32], copiedCredential);
        assertTrue(kit.isClosed());
    }

    private RecoveryKit kit() {
        return new RecoveryKit(RecoveryKit.FORMAT_VERSION, "enrollment", 1, new byte[32]);
    }
}
