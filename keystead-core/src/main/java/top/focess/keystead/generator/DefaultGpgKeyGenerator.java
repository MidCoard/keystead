package top.focess.keystead.generator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Objects;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.memory.SecretMemoryProvider;
import top.focess.keystead.memory.WipeableByteArrayOutputStream;

public final class DefaultGpgKeyGenerator implements GpgKeyGenerator {

    private static final String PROVIDER = BouncyCastleProvider.PROVIDER_NAME;

    private final SecureRandom random;
    private final SecretMemoryProvider memoryProvider;
    private final GpgKeyPairFactory keyPairFactory;

    public DefaultGpgKeyGenerator() {
        this(new SecureRandom());
    }

    public DefaultGpgKeyGenerator(@NonNull SecureRandom random) {
        this(random, SecretMemoryProvider.systemDefault(), GpgKeyPair::new);
    }

    DefaultGpgKeyGenerator(
            @NonNull SecureRandom random,
            @NonNull SecretMemoryProvider memoryProvider,
            @NonNull GpgKeyPairFactory keyPairFactory) {
        this.random = Objects.requireNonNull(random, "random");
        this.memoryProvider = Objects.requireNonNull(memoryProvider, "memoryProvider");
        this.keyPairFactory = Objects.requireNonNull(keyPairFactory, "keyPairFactory");
        ensureProvider();
    }

    @Override
    public @NonNull GpgKeyPair generate(@NonNull GpgKeyPolicy policy) {
        Objects.requireNonNull(policy, "policy");
        try {
            java.security.KeyPair keyPair = generateRsaKeyPair(policy.rsaBits());
            PGPKeyPair pgpKeyPair =
                    new JcaPGPKeyPair(
                            PublicKeyPacket.VERSION_4,
                            PGPPublicKey.RSA_GENERAL,
                            keyPair,
                            policy.createdAt());
            PGPDigestCalculator sha1 =
                    new JcaPGPDigestCalculatorProviderBuilder()
                            .setProvider(PROVIDER)
                            .build()
                            .get(HashAlgorithmTags.SHA1);
            char[][] passphraseHolder = new char[1][];
            policy.copyPassphrase(passphrase -> passphraseHolder[0] = passphrase.clone());
            try {
                PGPKeyRingGenerator ringGenerator =
                        new PGPKeyRingGenerator(
                                PGPSignature.POSITIVE_CERTIFICATION,
                                pgpKeyPair,
                                policy.identity(),
                                sha1,
                                null,
                                null,
                                new JcaPGPContentSignerBuilder(
                                                pgpKeyPair.getPublicKey().getAlgorithm(),
                                                HashAlgorithmTags.SHA256)
                                        .setProvider(PROVIDER),
                                new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1)
                                        .setProvider(PROVIDER)
                                        .setSecureRandom(random)
                                        .build(passphraseHolder[0]));
                SecretBuffer privateKey = null;
                boolean transferred = false;
                try {
                    String publicKey = armoredPublicKey(ringGenerator);
                    privateKey = armoredPrivateKey(ringGenerator);
                    GpgKeyPair result =
                            Objects.requireNonNull(
                                    keyPairFactory.create(publicKey, privateKey), "GPG key pair");
                    transferred = true;
                    return result;
                } finally {
                    if (!transferred && privateKey != null) {
                        privateKey.close();
                    }
                }
            } finally {
                if (passphraseHolder[0] != null) {
                    Arrays.fill(passphraseHolder[0], '\0');
                }
            }
        } catch (GeneralSecurityException | IOException | PGPException e) {
            throw new IllegalStateException("Could not generate GPG key pair", e);
        }
    }

    private java.security.@NonNull KeyPair generateRsaKeyPair(int rsaBits)
            throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(rsaBits, random);
        return generator.generateKeyPair();
    }

    private @NonNull String armoredPublicKey(@NonNull PGPKeyRingGenerator ringGenerator)
            throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (ArmoredOutputStream armor = ArmoredOutputStream.builder().build(output)) {
            ringGenerator.generatePublicKeyRing().encode(armor);
        }
        return output.toString(java.nio.charset.StandardCharsets.UTF_8);
    }

    private @NonNull SecretBuffer armoredPrivateKey(@NonNull PGPKeyRingGenerator ringGenerator)
            throws IOException {
        try (WipeableByteArrayOutputStream output = new WipeableByteArrayOutputStream()) {
            try (ArmoredOutputStream armor = ArmoredOutputStream.builder().build(output)) {
                ringGenerator.generateSecretKeyRing().encode(armor);
            }
            return output.toSecretBuffer(memoryProvider);
        }
    }

    @FunctionalInterface
    interface GpgKeyPairFactory {

        @NonNull GpgKeyPair create(@NonNull String publicKey, @NonNull SecretBuffer privateKey);
    }

    private static void ensureProvider() {
        if (Security.getProvider(PROVIDER) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
}
