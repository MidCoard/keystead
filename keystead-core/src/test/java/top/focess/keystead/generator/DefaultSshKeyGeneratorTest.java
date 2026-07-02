package top.focess.keystead.generator;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class DefaultSshKeyGeneratorTest {

    private final SshKeyGenerator generator = new DefaultSshKeyGenerator();

    @Test
    void generatesEd25519KeyPairWithOpenSshPublicKeyAndPemPrivateKey() throws Exception {
        try (SshKeyPair keyPair =
                generator.generate(new SshKeyPolicy(SshKeyAlgorithm.ED25519, "alice@laptop"))) {

            assertTrue(keyPair.publicKey().startsWith("ssh-ed25519 "));
            assertTrue(keyPair.publicKey().endsWith(" alice@laptop"));
            assertEquals("ssh-ed25519", openSshType(keyPair.publicKey()));
            assertEquals(32, openSshRawKey(keyPair.publicKey()).length);

            PrivateKey privateKey = readPrivateKey(keyPair);
            PublicKey publicKey = readPublicKey(keyPair.publicKey());
            byte[] message = "keystead ssh generation".getBytes(StandardCharsets.UTF_8);

            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(privateKey);
            signer.update(message);
            byte[] signature = signer.sign();

            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(publicKey);
            verifier.update(message);
            assertTrue(verifier.verify(signature));
        }
    }

    @Test
    void generatedPrivateKeyBufferIsDestroyedWhenPairIsClosed() {
        SshKeyPair keyPair =
                generator.generate(new SshKeyPolicy(SshKeyAlgorithm.ED25519, "alice@laptop"));
        keyPair.close();

        assertThrows(
                IllegalStateException.class, () -> keyPair.privateKey().copyChars(chars -> {}));
    }

    private static PrivateKey readPrivateKey(SshKeyPair keyPair) throws Exception {
        StringBuilder pem = new StringBuilder();
        keyPair.privateKey().copyChars(chars -> pem.append(chars));
        String base64 =
                pem.toString()
                        .replace("-----BEGIN PRIVATE KEY-----", "")
                        .replace("-----END PRIVATE KEY-----", "")
                        .replaceAll("\\s", "");
        return KeyFactory.getInstance("Ed25519")
                .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64)));
    }

    private static PublicKey readPublicKey(String openSshPublicKey) throws Exception {
        byte[] raw = openSshRawKey(openSshPublicKey);
        boolean xOdd = (raw[31] & 0x80) != 0;
        raw[31] &= 0x7f;
        byte[] bigEndian = raw.clone();
        reverse(bigEndian);
        EdECPoint point = new EdECPoint(xOdd, new BigInteger(1, bigEndian));
        return KeyFactory.getInstance("Ed25519")
                .generatePublic(new EdECPublicKeySpec(NamedParameterSpec.ED25519, point));
    }

    private static String openSshType(String openSshPublicKey) {
        ByteBuffer buffer = openSshWire(openSshPublicKey);
        return readString(buffer);
    }

    private static byte[] openSshRawKey(String openSshPublicKey) {
        ByteBuffer buffer = openSshWire(openSshPublicKey);
        assertEquals("ssh-ed25519", readString(buffer));
        byte[] raw = readBytes(buffer);
        assertFalse(buffer.hasRemaining());
        return raw;
    }

    private static ByteBuffer openSshWire(String openSshPublicKey) {
        String[] parts = openSshPublicKey.split(" ");
        assertTrue(parts.length >= 2);
        return ByteBuffer.wrap(Base64.getDecoder().decode(parts[1])).order(ByteOrder.BIG_ENDIAN);
    }

    private static String readString(ByteBuffer buffer) {
        return new String(readBytes(buffer), StandardCharsets.US_ASCII);
    }

    private static byte[] readBytes(ByteBuffer buffer) {
        int length = buffer.getInt();
        byte[] value = new byte[length];
        buffer.get(value);
        return value;
    }

    private static void reverse(byte[] bytes) {
        for (int i = 0; i < bytes.length / 2; i++) {
            byte value = bytes[i];
            bytes[i] = bytes[bytes.length - 1 - i];
            bytes[bytes.length - 1 - i] = value;
        }
    }
}
