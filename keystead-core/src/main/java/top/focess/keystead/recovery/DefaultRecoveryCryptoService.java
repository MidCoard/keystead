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

    public DefaultRecoveryCryptoService() {
        this(new SecureRandom());
    }

    public DefaultRecoveryCryptoService(@NonNull SecureRandom random) {
        this.random = Objects.requireNonNull(random, "random");
        this.crypto = new DefaultCryptoService(random);
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
            return new RecoveryEnrollmentMaterial(kit, credential, publicKey, encryptedPrivateKey);
        } catch (RuntimeException error) {
            kit.close();
            throw error;
        } finally {
            wipe(secret);
            wipe(credential);
            wipe(publicKeyBytes);
            wipe(encryptedPrivateKey);
        }
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
                packageContext(
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
                wipe(ciphertext);
            }
        } finally {
            wipe(publicKey);
            wipe(context);
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
        byte[] privateKey = decryptPrivateKey(kit, encryptedPrivateKey);
        byte[] ciphertext = keyPackage.encryptedVaultKey();
        byte[] context =
                packageContext(
                        keyPackage.username(),
                        keyPackage.vaultId(),
                        keyPackage.enrollmentId(),
                        keyPackage.generation(),
                        keyPackage.vaultKeyId().value());
        try {
            return vaultService.provisionVault(
                    vaultId,
                    new DeviceVaultKeyPackage(
                            keyPackage.vaultKeyId(), keyPackage.keyAlgorithm(), ciphertext),
                    privateKey,
                    context);
        } finally {
            wipe(privateKey);
            wipe(ciphertext);
            wipe(context);
        }
    }

    @Override
    public @NonNull String toString() {
        return "DefaultRecoveryCryptoService(<redacted>)";
    }

    private byte @NonNull [] encryptPrivateKey(
            @NonNull RecoveryKit kit, byte @NonNull [] privateKey) {
        byte[] key = derive(kit, "private-envelope-key");
        byte[] nonce = new byte[NONCE_BYTES];
        random.nextBytes(nonce);
        byte[] aad = privateEnvelopeAad(kit);
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(
                    Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, nonce));
            cipher.updateAAD(aad);
            byte[] ciphertext = cipher.doFinal(privateKey);
            try {
                ByteBuffer output =
                        ByteBuffer.allocate(
                                PRIVATE_ENVELOPE_MAGIC.length
                                        + Integer.BYTES
                                        + NONCE_BYTES
                                        + Integer.BYTES
                                        + ciphertext.length);
                output.put(PRIVATE_ENVELOPE_MAGIC)
                        .putInt(PRIVATE_ENVELOPE_VERSION)
                        .put(nonce)
                        .putInt(ciphertext.length)
                        .put(ciphertext);
                return output.array();
            } finally {
                wipe(ciphertext);
            }
        } catch (GeneralSecurityException error) {
            throw new CryptoException("Could not encrypt recovery private key", error);
        } finally {
            wipe(key);
            wipe(nonce);
            wipe(aad);
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
        ByteBuffer input =
                ByteBuffer.wrap(Arrays.copyOf(encryptedPrivateKey, encryptedPrivateKey.length));
        byte[] magic = new byte[PRIVATE_ENVELOPE_MAGIC.length];
        input.get(magic);
        int version = input.getInt();
        byte[] nonce = new byte[NONCE_BYTES];
        input.get(nonce);
        int ciphertextLength = input.getInt();
        if (!Arrays.equals(magic, PRIVATE_ENVELOPE_MAGIC)
                || version != PRIVATE_ENVELOPE_VERSION
                || ciphertextLength != input.remaining()) {
            wipe(magic);
            wipe(nonce);
            throw new CryptoException("Recovery private key envelope is invalid");
        }
        byte[] ciphertext = new byte[ciphertextLength];
        input.get(ciphertext);
        byte[] key = derive(kit, "private-envelope-key");
        byte[] aad = privateEnvelopeAad(kit);
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(
                    Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(ciphertext);
        } catch (GeneralSecurityException error) {
            throw new CryptoException("Could not decrypt recovery private key", error);
        } finally {
            wipe(magic);
            wipe(nonce);
            wipe(ciphertext);
            wipe(key);
            wipe(aad);
            if (input.hasArray()) {
                wipe(input.array());
            }
        }
    }

    private byte @NonNull [] derive(@NonNull RecoveryKit kit, @NonNull String info) {
        byte[] secret = kit.recoverySecret();
        byte[] salt = digest(binding(kit));
        byte[] pseudoRandomKey = hmac(salt, secret);
        byte[] input = ("keystead-recovery-v1|" + info).getBytes(StandardCharsets.UTF_8);
        byte[] expandInput = Arrays.copyOf(input, input.length + 1);
        expandInput[expandInput.length - 1] = 1;
        byte @Nullable [] expanded = null;
        try {
            expanded = hmac(pseudoRandomKey, expandInput);
            return Arrays.copyOf(expanded, DERIVED_KEY_BYTES);
        } finally {
            wipe(secret);
            wipe(salt);
            wipe(pseudoRandomKey);
            wipe(input);
            wipe(expandInput);
            wipe(expanded);
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
            wipe(value);
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

    private byte @NonNull [] packageContext(
            @NonNull String username,
            @NonNull String vaultId,
            @NonNull String enrollmentId,
            long generation,
            @NonNull String keyId) {
        return ("keystead-recovery-vault-package-v1|user:"
                        + username
                        + "|vault:"
                        + vaultId
                        + "|enrollment:"
                        + enrollmentId
                        + "|generation:"
                        + generation
                        + "|key:"
                        + keyId)
                .getBytes(StandardCharsets.UTF_8);
    }

    private void wipe(byte @Nullable [] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }
}
