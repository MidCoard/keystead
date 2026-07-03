package top.focess.keystead.generator;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.SecretBuffer;

public final class DefaultCertificateGenerator implements CertificateGenerator {

    private static final String PROVIDER = BouncyCastleProvider.PROVIDER_NAME;
    private static final int SERIAL_BITS = 160;
    private static final int PEM_LINE_LENGTH = 64;

    private final SecureRandom random;

    public DefaultCertificateGenerator() {
        this(new SecureRandom());
    }

    public DefaultCertificateGenerator(@NonNull SecureRandom random) {
        this.random = Objects.requireNonNull(random, "random");
        ensureProvider();
    }

    @Override
    public @NonNull CertificateBundle generate(@NonNull CertificatePolicy policy) {
        Objects.requireNonNull(policy, "policy");
        try {
            java.security.KeyPair keyPair = generateRsaKeyPair(policy.rsaBits());
            X500Name name = new X500Name("CN=" + policy.commonName());
            ContentSigner signer =
                    new JcaContentSignerBuilder("SHA256withRSA")
                            .setProvider(PROVIDER)
                            .build(keyPair.getPrivate());
            X509CertificateHolder holder =
                    new JcaX509v3CertificateBuilder(
                                    name,
                                    serialNumber(),
                                    policy.notBefore(),
                                    policy.notAfter(),
                                    name,
                                    keyPair.getPublic())
                            .build(signer);
            return new CertificateBundle(
                    pem("CERTIFICATE", holder.getEncoded()),
                    privateKeyPem(keyPair.getPrivate().getEncoded()));
        } catch (GeneralSecurityException | OperatorCreationException | java.io.IOException e) {
            throw new IllegalStateException("Could not generate certificate", e);
        }
    }

    private java.security.@NonNull KeyPair generateRsaKeyPair(int rsaBits)
            throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(rsaBits, random);
        return generator.generateKeyPair();
    }

    private @NonNull BigInteger serialNumber() {
        return new BigInteger(SERIAL_BITS, random).setBit(SERIAL_BITS - 1);
    }

    private @NonNull SecretBuffer privateKeyPem(byte @NonNull [] encodedPrivateKey) {
        byte[] pem = pemBytes("PRIVATE KEY", encodedPrivateKey);
        try {
            return SecretBuffer.fromUtf8(pem);
        } finally {
            Arrays.fill(encodedPrivateKey, (byte) 0);
            Arrays.fill(pem, (byte) 0);
        }
    }

    private @NonNull String pem(@NonNull String label, byte @NonNull [] der) {
        byte[] pem = pemBytes(label, der);
        try {
            return new String(pem, java.nio.charset.StandardCharsets.US_ASCII);
        } finally {
            Arrays.fill(der, (byte) 0);
            Arrays.fill(pem, (byte) 0);
        }
    }

    private byte @NonNull [] pemBytes(@NonNull String label, byte @NonNull [] der) {
        byte[] base64 = Base64.getMimeEncoder(PEM_LINE_LENGTH, new byte[] {'\n'}).encode(der);
        String header = "-----BEGIN " + label + "-----\n";
        String footer = "\n-----END " + label + "-----\n";
        byte[] headerBytes = header.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] footerBytes = footer.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] output = new byte[headerBytes.length + base64.length + footerBytes.length];
        System.arraycopy(headerBytes, 0, output, 0, headerBytes.length);
        System.arraycopy(base64, 0, output, headerBytes.length, base64.length);
        System.arraycopy(
                footerBytes, 0, output, headerBytes.length + base64.length, footerBytes.length);
        Arrays.fill(base64, (byte) 0);
        return output;
    }

    private static void ensureProvider() {
        if (Security.getProvider(PROVIDER) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
}
