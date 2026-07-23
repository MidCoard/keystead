package top.focess.keystead.recovery;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.crypto.CryptoException;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.crypto.DeviceKeyPair;
import top.focess.keystead.memory.Wipe;
import top.focess.keystead.model.VaultId;
import top.focess.keystead.service.DeviceVaultKeyPackage;
import top.focess.keystead.service.VaultHandle;
import top.focess.keystead.service.VaultService;

/** Default zero-knowledge recovery implementation. */
public final class DefaultRecoveryCryptoService implements RecoveryCryptoService {

    private static final byte[] PRIVATE_ENVELOPE_MAGIC = {'K', 'R', 'P', '1'};
    private static final int PRIVATE_ENVELOPE_VERSION = 1;
    private static final int NONCE_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final int DERIVED_KEY_BYTES = 32;
    private static final int MAX_PRIVATE_ENVELOPE_BYTES = 1024 * 1024;
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";

    private final SecureRandom random;
    private final DefaultCryptoService crypto;
    private final RecoveryEnrollmentMaterialFactory enrollmentMaterialFactory;

    /** Creates a recovery service with a default secure random. */
    public DefaultRecoveryCryptoService() {
        this(new SecureRandom());
    }

    /**
     * Creates a recovery service with the supplied secure random.
     *
     * @param random the secure random source
     */
    public DefaultRecoveryCryptoService(@NonNull SecureRandom random) {
        this(random, RecoveryEnrollmentMaterial::new);
    }

    DefaultRecoveryCryptoService(
            @NonNull SecureRandom random,
            @NonNull RecoveryEnrollmentMaterialFactory enrollmentMaterialFactory) {
        this.random = Objects.requireNonNull(random, "random");
        this.crypto = new DefaultCryptoService(random);
        this.enrollmentMaterialFactory =
                Objects.requireNonNull(enrollmentMaterialFactory, "enrollmentMaterialFactory");
    }

    @Override
    public @NonNull RecoveryEnrollmentMaterial enroll(
            @NonNull String enrollmentId, long generation) {
        RecoveryKit.requireIdentifier(enrollmentId);
        if (generation <= 0) {
            throw new IllegalArgumentException("Recovery generation must be positive");
        }
        byte[] secret = new byte[RecoveryKit.SECRET_BYTES];
        random.nextBytes(secret);
        RecoveryKit kit =
                new RecoveryKit(RecoveryKit.FORMAT_VERSION, enrollmentId, generation, secret);
        byte @Nullable [] credential = null;
        byte @Nullable [] publicKeyBytes = null;
        byte @Nullable [] encryptedPrivateKey = null;
        boolean transferred = false;
        try (DeviceKeyPair keyPair = crypto.generateDeviceKeyPair()) {
            credential = accountCredential(kit);
            publicKeyBytes = keyPair.publicKey();
            AtomicReference<byte @Nullable []> encryptedPrivateKeyResult = new AtomicReference<>();
            keyPair.copyPrivateKey(
                    privateKey ->
                            encryptedPrivateKeyResult.set(encryptPrivateKey(kit, privateKey)));
            encryptedPrivateKey =
                    Objects.requireNonNull(
                            encryptedPrivateKeyResult.get(),
                            "Device private-key encryption did not produce a result");
            RecoveryPublicKey publicKey =
                    new RecoveryPublicKey(
                            enrollmentId, generation, keyPair.keyAlgorithm(), publicKeyBytes);
            RecoveryEnrollmentMaterial material =
                    Objects.requireNonNull(
                            enrollmentMaterialFactory.create(
                                    kit, credential, publicKey, encryptedPrivateKey),
                            "recovery enrollment material");
            transferred = true;
            return material;
        } finally {
            if (!transferred) {
                kit.close();
            }
            Wipe.wipe(secret);
            Wipe.wipe(credential);
            Wipe.wipe(publicKeyBytes);
            Wipe.wipe(encryptedPrivateKey);
        }
    }

    @FunctionalInterface
    interface RecoveryEnrollmentMaterialFactory {

        @NonNull RecoveryEnrollmentMaterial create(
                @NonNull RecoveryKit kit,
                byte @NonNull [] accountCredential,
                @NonNull RecoveryPublicKey publicKey,
                byte @NonNull [] encryptedPrivateKey);
    }

    @Override
    public byte @NonNull [] accountCredential(@NonNull RecoveryKit kit) {
        Objects.requireNonNull(kit, "kit");
        return derive(kit, "account-credential");
    }

    @Override
    public @NonNull RecoveryVaultKeyPackage wrapVaultKey(
            @NonNull VaultHandle vault,
            @NonNull RecoveryPublicKey recoveryKey,
            @NonNull String username,
            @NonNull String vaultId) {
        Objects.requireNonNull(vault, "vault");
        Objects.requireNonNull(recoveryKey, "recoveryKey");
        Objects.requireNonNull(username, "username");
        Objects.requireNonNull(vaultId, "vaultId");
        if (!vault.vaultId().value().toString().equals(vaultId)) {
            throw new IllegalArgumentException("Recovery package vault does not match");
        }
        byte[] publicKey = recoveryKey.publicKey();
        byte[] context =
                RecoveryContextCodec.version2(
                        username,
                        vaultId,
                        recoveryKey.enrollmentId(),
                        recoveryKey.generation(),
                        vault.vaultKeyId().value());
        try {
            DeviceVaultKeyPackage wrapped = vault.wrapVaultKeyPackageForDevice(publicKey, context);
            byte[] ciphertext = wrapped.encryptedVaultKey();
            try {
                return new RecoveryVaultKeyPackage(
                        username,
                        vaultId,
                        wrapped.vaultKeyId(),
                        recoveryKey.enrollmentId(),
                        recoveryKey.generation(),
                        wrapped.keyAlgorithm(),
                        ciphertext);
            } finally {
                Wipe.wipe(ciphertext);
            }
        } finally {
            Wipe.wipe(publicKey);
            Wipe.wipe(context);
        }
    }

    @Override
    public @NonNull VaultHandle openVault(
            @NonNull VaultService vaultService,
            @NonNull VaultId vaultId,
            @NonNull RecoveryVaultKeyPackage keyPackage,
            @NonNull RecoveryKit kit,
            byte @NonNull [] encryptedPrivateKey) {
        Objects.requireNonNull(vaultService, "vaultService");
        Objects.requireNonNull(vaultId, "vaultId");
        Objects.requireNonNull(keyPackage, "keyPackage");
        Objects.requireNonNull(kit, "kit");
        Objects.requireNonNull(encryptedPrivateKey, "encryptedPrivateKey");
        if (!vaultId.value().toString().equals(keyPackage.vaultId())
                || !kit.enrollmentId().equals(keyPackage.enrollmentId())
                || kit.generation() != keyPackage.generation()) {
            throw new CryptoException("Recovery material does not match");
        }
        byte @Nullable [] privateKey = null;
        byte @Nullable [] ciphertext = null;
        byte @Nullable [] version2Context = null;
        byte @Nullable [] legacyContext = null;
        try {
            privateKey = decryptPrivateKey(kit, encryptedPrivateKey);
            ciphertext = keyPackage.encryptedVaultKey();
            version2Context =
                    RecoveryContextCodec.version2(
                            keyPackage.username(),
                            keyPackage.vaultId(),
                            keyPackage.enrollmentId(),
                            keyPackage.generation(),
                            keyPackage.vaultKeyId().value());
            try {
                return vaultService.provisionVault(
                        vaultId,
                        keyPackage.vaultKeyId(),
                        keyPackage.keyAlgorithm(),
                        ciphertext,
                        privateKey,
                        version2Context);
            } catch (CryptoException version2Failure) {
                legacyContext =
                        RecoveryContextCodec.legacyVersion1(
                                keyPackage.username(),
                                keyPackage.vaultId(),
                                keyPackage.enrollmentId(),
                                keyPackage.generation(),
                                keyPackage.vaultKeyId().value());
                try {
                    return vaultService.provisionVault(
                            vaultId,
                            keyPackage.vaultKeyId(),
                            keyPackage.keyAlgorithm(),
                            ciphertext,
                            privateKey,
                            legacyContext);
                } catch (CryptoException legacyFailure) {
                    throw new CryptoException(
                            "Could not open recovery vault package", legacyFailure);
                }
            }
        } finally {
            Wipe.wipe(privateKey);
            Wipe.wipe(ciphertext);
            Wipe.wipe(version2Context);
            Wipe.wipe(legacyContext);
        }
    }

    @Override
    public @NonNull String toString() {
        return "DefaultRecoveryCryptoService(<redacted>)";
    }

    private byte @NonNull [] encryptPrivateKey(
            @NonNull RecoveryKit kit, byte @NonNull [] privateKey) {
        byte @Nullable [] key = null;
        byte @Nullable [] nonce = null;
        byte @Nullable [] aad = null;
        byte @Nullable [] ciphertext = null;
        byte @Nullable [] output = null;
        boolean completed = false;
        try {
            key = derive(kit, "private-envelope-key");
            nonce = new byte[NONCE_BYTES];
            random.nextBytes(nonce);
            aad = privateEnvelopeAad(kit);
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(
                    Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, nonce));
            cipher.updateAAD(aad);
            ciphertext = cipher.doFinal(privateKey);
            output =
                    new byte
                            [PRIVATE_ENVELOPE_MAGIC.length
                                    + Integer.BYTES
                                    + NONCE_BYTES
                                    + Integer.BYTES
                                    + ciphertext.length];
            ByteBuffer.wrap(output)
                    .put(PRIVATE_ENVELOPE_MAGIC)
                    .putInt(PRIVATE_ENVELOPE_VERSION)
                    .put(nonce)
                    .putInt(ciphertext.length)
                    .put(ciphertext);
            completed = true;
            return output;
        } catch (GeneralSecurityException error) {
            throw new CryptoException("Could not encrypt recovery private key", error);
        } finally {
            Wipe.wipe(key);
            Wipe.wipe(nonce);
            Wipe.wipe(aad);
            Wipe.wipe(ciphertext);
            if (!completed) {
                Wipe.wipe(output);
            }
        }
    }

    private byte @NonNull [] decryptPrivateKey(
            @NonNull RecoveryKit kit, byte @NonNull [] encryptedPrivateKey) {
        if (encryptedPrivateKey.length
                        < PRIVATE_ENVELOPE_MAGIC.length
                                + Integer.BYTES
                                + NONCE_BYTES
                                + Integer.BYTES
                                + 16
                || encryptedPrivateKey.length > MAX_PRIVATE_ENVELOPE_BYTES) {
            throw new CryptoException("Recovery private key envelope is invalid");
        }
        byte @Nullable [] inputCopy = null;
        byte @Nullable [] magic = null;
        byte @Nullable [] nonce = null;
        byte @Nullable [] ciphertext = null;
        byte @Nullable [] key = null;
        byte @Nullable [] aad = null;
        byte @Nullable [] plaintext = null;
        boolean completed = false;
        try {
            inputCopy = Arrays.copyOf(encryptedPrivateKey, encryptedPrivateKey.length);
            ByteBuffer input = ByteBuffer.wrap(inputCopy);
            magic = new byte[PRIVATE_ENVELOPE_MAGIC.length];
            input.get(magic);
            int version = input.getInt();
            nonce = new byte[NONCE_BYTES];
            input.get(nonce);
            int ciphertextLength = input.getInt();
            if (!Arrays.equals(magic, PRIVATE_ENVELOPE_MAGIC)
                    || version != PRIVATE_ENVELOPE_VERSION
                    || ciphertextLength != input.remaining()) {
                throw new CryptoException("Recovery private key envelope is invalid");
            }
            ciphertext = new byte[ciphertextLength];
            input.get(ciphertext);
            key = derive(kit, "private-envelope-key");
            aad = privateEnvelopeAad(kit);
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(
                    Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, nonce));
            cipher.updateAAD(aad);
            plaintext = cipher.doFinal(ciphertext);
            completed = true;
            return plaintext;
        } catch (GeneralSecurityException error) {
            throw new CryptoException("Could not decrypt recovery private key", error);
        } finally {
            Wipe.wipe(inputCopy);
            Wipe.wipe(magic);
            Wipe.wipe(nonce);
            Wipe.wipe(ciphertext);
            Wipe.wipe(key);
            Wipe.wipe(aad);
            if (!completed) {
                Wipe.wipe(plaintext);
            }
        }
    }

    private byte @NonNull [] derive(@NonNull RecoveryKit kit, @NonNull String info) {
        byte @Nullable [] secret = null;
        byte @Nullable [] salt = null;
        byte @Nullable [] pseudoRandomKey = null;
        byte @Nullable [] input = null;
        byte @Nullable [] expandInput = null;
        byte @Nullable [] expanded = null;
        byte @Nullable [] output = null;
        boolean completed = false;
        try {
            secret = kit.recoverySecret();
            salt = digest(binding(kit));
            pseudoRandomKey = hmac(salt, secret);
            input = ("keystead-recovery-v1|" + info).getBytes(StandardCharsets.UTF_8);
            expandInput = Arrays.copyOf(input, input.length + 1);
            expandInput[expandInput.length - 1] = 1;
            expanded = hmac(pseudoRandomKey, expandInput);
            output = Arrays.copyOf(expanded, DERIVED_KEY_BYTES);
            completed = true;
            return output;
        } finally {
            Wipe.wipe(secret);
            Wipe.wipe(salt);
            Wipe.wipe(pseudoRandomKey);
            Wipe.wipe(input);
            Wipe.wipe(expandInput);
            Wipe.wipe(expanded);
            if (!completed) {
                Wipe.wipe(output);
            }
        }
    }

    private byte @NonNull [] hmac(byte @NonNull [] key, byte @NonNull [] value) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
            return mac.doFinal(value);
        } catch (GeneralSecurityException error) {
            throw new CryptoException("Could not derive recovery key", error);
        }
    }

    private byte @NonNull [] digest(byte @NonNull [] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (NoSuchAlgorithmException error) {
            throw new CryptoException("Could not derive recovery key", error);
        } finally {
            Wipe.wipe(value);
        }
    }

    private byte @NonNull [] privateEnvelopeAad(@NonNull RecoveryKit kit) {
        return (bindingText(kit) + "|algorithm:" + DefaultCryptoService.DEVICE_KEY_ALGORITHM)
                .getBytes(StandardCharsets.UTF_8);
    }

    private byte @NonNull [] binding(@NonNull RecoveryKit kit) {
        return bindingText(kit).getBytes(StandardCharsets.UTF_8);
    }

    private @NonNull String bindingText(@NonNull RecoveryKit kit) {
        return "keystead-recovery-v1|enrollment:"
                + kit.enrollmentId()
                + "|generation:"
                + kit.generation();
    }
}
