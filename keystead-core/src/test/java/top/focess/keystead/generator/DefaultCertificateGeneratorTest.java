package top.focess.keystead.generator;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.atomic.AtomicReference;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.Test;
import top.focess.keystead.memory.SecretBuffer;

class DefaultCertificateGeneratorTest {

    private final CertificateGenerator generator = new DefaultCertificateGenerator();

    @Test
    void generatesSelfSignedX509CertificateAndPemPrivateKey() throws Exception {
        Date notBefore = new Date(1_800_000_000_000L);
        Date notAfter = new Date(1_831_536_000_000L);
        try (CertificateBundle bundle =
                generator.generate(new CertificatePolicy("keystead.local", notBefore, notAfter))) {
            X509Certificate certificate = parseCertificate(bundle.certificate());
            PrivateKey privateKey = parsePrivateKey(bundle.privateKey());

            certificate.checkValidity(notBefore);
            certificate.verify(certificate.getPublicKey());
            assertEquals(
                    new X500Principal("CN=keystead.local"), certificate.getSubjectX500Principal());
            assertEquals(
                    certificate.getSubjectX500Principal(), certificate.getIssuerX500Principal());
            assertEquals("RSA", privateKey.getAlgorithm());
            assertTrue(copy(bundle.privateKey()).startsWith("-----BEGIN PRIVATE KEY-----"));
        }
    }

    @Test
    void policyRejectsInvalidValidityWindow() {
        Date notBefore = new Date(2_000L);
        Date notAfter = new Date(1_000L);

        assertThrows(
                IllegalArgumentException.class,
                () -> new CertificatePolicy("", new Date(1_000L), new Date(2_000L)));
        assertThrows(
                IllegalArgumentException.class,
                () -> new CertificatePolicy("keystead.local", notBefore, notAfter));
    }

    @Test
    void generatedPrivateKeyBufferIsDestroyedWhenBundleIsClosed() {
        CertificateBundle bundle =
                generator.generate(
                        new CertificatePolicy(
                                "keystead.local", new Date(1_000L), new Date(86_401_000L)));
        bundle.close();

        assertThrows(IllegalStateException.class, () -> bundle.privateKey().copyChars(chars -> {}));
    }

    private static X509Certificate parseCertificate(String pem) throws Exception {
        String base64 =
                pem.replace("-----BEGIN CERTIFICATE-----", "")
                        .replace("-----END CERTIFICATE-----", "")
                        .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(base64);
        return (X509Certificate)
                CertificateFactory.getInstance("X.509")
                        .generateCertificate(new ByteArrayInputStream(der));
    }

    private static PrivateKey parsePrivateKey(SecretBuffer privateKey) throws Exception {
        String pem = copy(privateKey);
        String base64 =
                pem.replace("-----BEGIN PRIVATE KEY-----", "")
                        .replace("-----END PRIVATE KEY-----", "")
                        .replaceAll("\\s", "");
        return KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64)));
    }

    private static String copy(SecretBuffer buffer) {
        AtomicReference<String> value = new AtomicReference<>("");
        buffer.copyChars(chars -> value.set(new String(chars)));
        return value.get();
    }
}
