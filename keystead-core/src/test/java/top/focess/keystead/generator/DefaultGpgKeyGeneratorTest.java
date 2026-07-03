package top.focess.keystead.generator;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicReference;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.junit.jupiter.api.Test;

class DefaultGpgKeyGeneratorTest {

    private final GpgKeyGenerator generator = new DefaultGpgKeyGenerator();

    @Test
    void generatesArmoredRsaOpenPgpKeyRings() throws Exception {
        Date createdAt = new Date(1_800_000_000_000L);
        char[] passphrase = "changeit".toCharArray();
        try (GpgKeyPolicy policy =
                        new GpgKeyPolicy("Alice <alice@example.com>", passphrase, createdAt);
                GpgKeyPair keyPair = generator.generate(policy)) {
            assertArrayEquals(new char[passphrase.length], passphrase);

            String publicKey = keyPair.publicKey();
            String privateKey = copy(keyPair.privateKey());

            assertTrue(publicKey.startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
            assertTrue(privateKey.startsWith("-----BEGIN PGP PRIVATE KEY BLOCK-----"));

            PGPPublicKeyRing publicRing = publicRing(publicKey);
            PGPSecretKeyRing secretRing = secretRing(privateKey);
            PGPPublicKey masterPublicKey = publicRing.getPublicKey();
            PGPSecretKey masterSecretKey = secretRing.getSecretKey();

            assertTrue(masterPublicKey.isMasterKey());
            assertTrue(masterSecretKey.isMasterKey());
            assertEquals(PGPPublicKey.RSA_GENERAL, masterPublicKey.getAlgorithm());
            assertEquals(createdAt, masterPublicKey.getCreationTime());
            assertEquals("Alice <alice@example.com>", firstUserId(masterPublicKey));
        }
    }

    @Test
    void policyRejectsBlankIdentity() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new GpgKeyPolicy("", "changeit".toCharArray()));
        assertThrows(IllegalArgumentException.class, () -> new GpgKeyPolicy("Alice", new char[0]));
    }

    @Test
    void generatedPrivateKeyBufferIsDestroyedWhenPairIsClosed() {
        char[] passphrase = "changeit".toCharArray();
        GpgKeyPair keyPair;
        try (GpgKeyPolicy policy = new GpgKeyPolicy("Alice <alice@example.com>", passphrase)) {
            keyPair = generator.generate(policy);
            assertArrayEquals(new char[passphrase.length], passphrase);
        }
        keyPair.close();

        assertThrows(
                IllegalStateException.class, () -> keyPair.privateKey().copyChars(chars -> {}));
    }

    private static String copy(top.focess.keystead.memory.SecretBuffer buffer) {
        AtomicReference<String> value = new AtomicReference<>("");
        buffer.copyChars(chars -> value.set(new String(chars)));
        return value.get();
    }

    private static PGPPublicKeyRing publicRing(String armored) throws Exception {
        try (ByteArrayInputStream input =
                new ByteArrayInputStream(armored.getBytes(StandardCharsets.UTF_8))) {
            PGPObjectFactory factory =
                    new PGPObjectFactory(
                            PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());
            return (PGPPublicKeyRing) factory.nextObject();
        }
    }

    private static PGPSecretKeyRing secretRing(String armored) throws Exception {
        try (ByteArrayInputStream input =
                new ByteArrayInputStream(armored.getBytes(StandardCharsets.UTF_8))) {
            PGPObjectFactory factory =
                    new PGPObjectFactory(
                            PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());
            return (PGPSecretKeyRing) factory.nextObject();
        }
    }

    private static String firstUserId(PGPPublicKey publicKey) {
        Iterator<String> userIds = publicKey.getUserIDs();
        assertTrue(userIds.hasNext());
        return userIds.next();
    }
}
