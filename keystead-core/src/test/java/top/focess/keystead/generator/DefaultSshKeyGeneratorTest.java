package top.focess.keystead.generator;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil;
import org.bouncycastle.crypto.util.OpenSSHPublicKeyUtil;
import org.junit.jupiter.api.Test;

class DefaultSshKeyGeneratorTest {

    private final SshKeyGenerator generator = new DefaultSshKeyGenerator();

    @Test
    void generatesEd25519KeyPairWithOpenSshPrivateKey() throws Exception {
        try (SshKeyPair keyPair =
                generator.generate(new SshKeyPolicy(SshKeyAlgorithm.ED25519, "alice@laptop"))) {

            assertTrue(keyPair.publicKey().startsWith("ssh-ed25519 "));
            assertTrue(keyPair.publicKey().endsWith(" alice@laptop"));
            assertEquals("ssh-ed25519", openSshType(keyPair.publicKey()));
            assertEquals(32, openSshRawKey(keyPair.publicKey()).length);

            StringBuilder pem = new StringBuilder();
            keyPair.privateKey().copyChars(pem::append);
            String privateKeyPem = pem.toString();
            assertTrue(privateKeyPem.startsWith("-----BEGIN OPENSSH PRIVATE KEY-----"));
            assertTrue(privateKeyPem.contains("-----END OPENSSH PRIVATE KEY-----"));

            // The private key must round-trip through BouncyCastle's OpenSSH parser and derive
            // exactly the public key advertised in the authorized_keys-style public string.
            byte[] privateBlob = openSshPrivateBlob(privateKeyPem);
            AsymmetricKeyParameter privateParams =
                    OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(privateBlob);
            assertInstanceOf(Ed25519PrivateKeyParameters.class, privateParams);
            Ed25519PublicKeyParameters derivedPublic =
                    ((Ed25519PrivateKeyParameters) privateParams).generatePublicKey();
            Ed25519PublicKeyParameters statedPublic = openSshPublicParams(keyPair.publicKey());
            assertArrayEquals(statedPublic.getEncoded(), derivedPublic.getEncoded());

            byte[] message = "keystead ssh generation".getBytes(StandardCharsets.US_ASCII);
            Ed25519Signer signer = new Ed25519Signer();
            signer.init(true, privateParams);
            signer.update(message, 0, message.length);
            byte[] signature = signer.generateSignature();
            Ed25519Signer verifier = new Ed25519Signer();
            verifier.init(false, statedPublic);
            verifier.update(message, 0, message.length);
            assertTrue(verifier.verifySignature(signature));
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

    private static byte[] openSshPrivateBlob(String pem) {
        String base64 =
                pem.replace("-----BEGIN OPENSSH PRIVATE KEY-----", "")
                        .replace("-----END OPENSSH PRIVATE KEY-----", "")
                        .replaceAll("\\s", "");
        return Base64.getDecoder().decode(base64);
    }

    private static Ed25519PublicKeyParameters openSshPublicParams(String openSshPublicKey) {
        String[] parts = openSshPublicKey.split(" ");
        assertTrue(parts.length >= 2);
        byte[] wire = Base64.getDecoder().decode(parts[1]);
        AsymmetricKeyParameter params = OpenSSHPublicKeyUtil.parsePublicKey(wire);
        assertInstanceOf(Ed25519PublicKeyParameters.class, params);
        return (Ed25519PublicKeyParameters) params;
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
}
