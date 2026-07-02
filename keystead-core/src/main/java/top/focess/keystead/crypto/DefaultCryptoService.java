package top.focess.keystead.crypto;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.model.EncryptedEnvelope;
import top.focess.keystead.model.KeyId;

public final class DefaultCryptoService {

    public static final String PAYLOAD_ALGORITHM = "AES-256-GCM";
    public static final String KDF_ALGORITHM = "PBKDF2WithHmacSHA256";
    public static final int DEFAULT_KDF_ITERATIONS = 120_000;

    private static final int KEY_BYTES = 32;
    private static final int SALT_BYTES = 16;
    private static final int NONCE_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;

    private final SecureRandom random;

    public DefaultCryptoService() {
        this(new SecureRandom());
    }

    public DefaultCryptoService(@NonNull SecureRandom random) {
        this.random = Objects.requireNonNull(random, "random");
    }

    public @NonNull VaultKey generateVaultKey(@NonNull KeyId keyId) {
        byte[] keyBytes = new byte[KEY_BYTES];
        random.nextBytes(keyBytes);
        try {
            return new VaultKey(keyId, keyBytes);
        } finally {
            Arrays.fill(keyBytes, (byte) 0);
        }
    }

    public byte @NonNull [] randomSalt() {
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        return salt;
    }

    public @NonNull EncryptedEnvelope encrypt(
            @NonNull VaultKey key,
            byte @NonNull [] plaintext,
            byte @NonNull [] aad,
            @NonNull Instant encryptedAt) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(plaintext, "plaintext");
        Objects.requireNonNull(aad, "aad");
        Objects.requireNonNull(encryptedAt, "encryptedAt");

        byte[] nonce = new byte[NONCE_BYTES];
        random.nextBytes(nonce);
        byte[] ciphertext =
                withKeyBytes(key, keyBytes -> encryptAesGcm(keyBytes, nonce, plaintext, aad));
        return new EncryptedEnvelope(
                1, PAYLOAD_ALGORITHM, key.keyId(), nonce, aad, ciphertext, encryptedAt);
    }

    public byte @NonNull [] decrypt(
            @NonNull VaultKey key, @NonNull EncryptedEnvelope envelope, byte @NonNull [] aad) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(envelope, "envelope");
        Objects.requireNonNull(aad, "aad");
        if (!PAYLOAD_ALGORITHM.equals(envelope.algorithm())) {
            throw new CryptoException("Unsupported encrypted envelope algorithm");
        }
        if (!Arrays.equals(envelope.aad(), aad)) {
            throw new CryptoException("Encrypted envelope AAD does not match expected AAD");
        }
        return withKeyBytes(
                key,
                keyBytes -> decryptAesGcm(keyBytes, envelope.nonce(), envelope.ciphertext(), aad));
    }

    public byte @NonNull [] wrapVaultKey(
            @NonNull VaultKey vaultKey,
            char @NonNull [] masterPassword,
            byte @NonNull [] salt,
            int iterations) {
        Objects.requireNonNull(vaultKey, "vaultKey");
        byte[] wrappingKey = deriveWrappingKey(masterPassword, salt, iterations);
        byte[] nonce = new byte[NONCE_BYTES];
        random.nextBytes(nonce);
        try {
            byte[] wrapped =
                    withKeyBytes(
                            vaultKey,
                            keyBytes ->
                                    encryptAesGcm(
                                            wrappingKey,
                                            nonce,
                                            keyBytes,
                                            wrappingAad(vaultKey.keyId())));
            byte[] output = new byte[nonce.length + wrapped.length];
            System.arraycopy(nonce, 0, output, 0, nonce.length);
            System.arraycopy(wrapped, 0, output, nonce.length, wrapped.length);
            return output;
        } finally {
            Arrays.fill(wrappingKey, (byte) 0);
            Arrays.fill(nonce, (byte) 0);
        }
    }

    public @NonNull VaultKey unwrapVaultKey(
            @NonNull KeyId keyId,
            byte @NonNull [] wrappedVaultKey,
            char @NonNull [] masterPassword,
            byte @NonNull [] salt,
            int iterations) {
        Objects.requireNonNull(keyId, "keyId");
        Objects.requireNonNull(wrappedVaultKey, "wrappedVaultKey");
        if (wrappedVaultKey.length <= NONCE_BYTES) {
            throw new CryptoException("Wrapped vault key is invalid");
        }

        byte[] wrappingKey = deriveWrappingKey(masterPassword, salt, iterations);
        byte[] nonce = Arrays.copyOfRange(wrappedVaultKey, 0, NONCE_BYTES);
        byte[] ciphertext =
                Arrays.copyOfRange(wrappedVaultKey, NONCE_BYTES, wrappedVaultKey.length);
        byte @Nullable [] opened = null;
        try {
            opened = decryptAesGcm(wrappingKey, nonce, ciphertext, wrappingAad(keyId));
            return new VaultKey(keyId, opened);
        } finally {
            Arrays.fill(wrappingKey, (byte) 0);
            Arrays.fill(nonce, (byte) 0);
            Arrays.fill(ciphertext, (byte) 0);
            if (opened != null) {
                Arrays.fill(opened, (byte) 0);
            }
        }
    }

    private byte @NonNull [] deriveWrappingKey(
            char @NonNull [] masterPassword, byte @NonNull [] salt, int iterations) {
        Objects.requireNonNull(masterPassword, "masterPassword");
        Objects.requireNonNull(salt, "salt");
        if (iterations <= 0) {
            throw new IllegalArgumentException("KDF iterations must be positive");
        }
        char[] passwordCopy = Arrays.copyOf(masterPassword, masterPassword.length);
        PBEKeySpec spec =
                new PBEKeySpec(
                        passwordCopy, Arrays.copyOf(salt, salt.length), iterations, KEY_BYTES * 8);
        try {
            return SecretKeyFactory.getInstance(KDF_ALGORITHM).generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Could not derive wrapping key", e);
        } finally {
            Arrays.fill(passwordCopy, '\0');
            spec.clearPassword();
        }
    }

    private byte @NonNull [] encryptAesGcm(
            byte @NonNull [] keyBytes,
            byte @NonNull [] nonce,
            byte @NonNull [] plaintext,
            byte @NonNull [] aad) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(
                    Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(keyBytes, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(plaintext);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Could not encrypt payload", e);
        }
    }

    private byte @NonNull [] decryptAesGcm(
            byte @NonNull [] keyBytes,
            byte @NonNull [] nonce,
            byte @NonNull [] ciphertext,
            byte @NonNull [] aad) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(
                    Cipher.DECRYPT_MODE,
                    new SecretKeySpec(keyBytes, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, nonce));
            cipher.updateAAD(aad);
            return cipher.doFinal(ciphertext);
        } catch (AEADBadTagException e) {
            throw new CryptoException("Could not decrypt payload", e);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Could not decrypt payload", e);
        }
    }

    private byte @NonNull [] wrappingAad(@NonNull KeyId keyId) {
        return keyId.value().getBytes(StandardCharsets.UTF_8);
    }

    private byte @NonNull [] withKeyBytes(@NonNull VaultKey key, @NonNull KeyOperation operation) {
        final byte[][] output = new byte[1][];
        key.copyBytes(keyBytes -> output[0] = operation.apply(keyBytes));
        return output[0];
    }

    @FunctionalInterface
    private interface KeyOperation {
        byte @NonNull [] apply(byte @NonNull [] keyBytes);
    }
}
