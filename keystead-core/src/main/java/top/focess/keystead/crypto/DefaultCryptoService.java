package top.focess.keystead.crypto;

import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.JsonKeysetWriter;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.hybrid.HybridConfig;
import com.google.crypto.tink.hybrid.HybridKeyTemplates;
import java.io.ByteArrayOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.memory.SecretMemoryProvider;
import top.focess.keystead.memory.WipeableByteArrayOutputStream;
import top.focess.keystead.model.EncryptedEnvelope;
import top.focess.keystead.model.KeyId;

public final class DefaultCryptoService {

    public static final String PAYLOAD_ALGORITHM = CryptoAlgorithmRegistry.AEAD_AES_256_GCM;
    public static final String DEVICE_KEY_ALGORITHM =
            CryptoAlgorithmRegistry.DEVICE_TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM;
    public static final String KDF_ALGORITHM = CryptoAlgorithmRegistry.KDF_PBKDF2_HMAC_SHA256;
    public static final int DEFAULT_KDF_ITERATIONS = 120_000;

    private static final int KEY_BYTES = 32;
    private static final int SALT_BYTES = 16;

    private final SecureRandom random;
    private final AeadCipher aeadCipher;
    private final SecretMemoryProvider memoryProvider;
    private final Map<String, AeadCipher> aeadCiphers;
    private final Map<String, PasswordKeyDerivation> passwordKeyDerivations;

    public DefaultCryptoService() {
        this(new SecureRandom());
    }

    public DefaultCryptoService(@NonNull SecureRandom random) {
        this(random, new TinkAesGcmCipher());
    }

    public DefaultCryptoService(@NonNull SecureRandom random, @NonNull AeadCipher aeadCipher) {
        this(random, aeadCipher, SecretMemoryProvider.heap());
    }

    public DefaultCryptoService(
            @NonNull SecureRandom random,
            @NonNull AeadCipher aeadCipher,
            @NonNull SecretMemoryProvider memoryProvider) {
        this(random, aeadCipher, memoryProvider, defaultPasswordKeyDerivations());
    }

    public DefaultCryptoService(
            @NonNull SecureRandom random,
            @NonNull AeadCipher aeadCipher,
            @NonNull SecretMemoryProvider memoryProvider,
            @NonNull Collection<PasswordKeyDerivation> passwordKeyDerivations) {
        this.random = Objects.requireNonNull(random, "random");
        this.aeadCipher = Objects.requireNonNull(aeadCipher, "aeadCipher");
        this.memoryProvider = Objects.requireNonNull(memoryProvider, "memoryProvider");
        this.aeadCiphers = aeadCiphers(aeadCipher);
        this.passwordKeyDerivations = passwordKeyDerivations(passwordKeyDerivations);
    }

    public @NonNull VaultKey generateVaultKey(@NonNull KeyId keyId) {
        byte[] keyBytes = new byte[KEY_BYTES];
        random.nextBytes(keyBytes);
        try {
            return new VaultKey(keyId, keyBytes, memoryProvider);
        } finally {
            Arrays.fill(keyBytes, (byte) 0);
        }
    }

    public byte @NonNull [] randomSalt() {
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        return salt;
    }

    public @NonNull DeviceKeyPair generateDeviceKeyPair() {
        try {
            registerHybridPrimitives();
            KeysetHandle privateHandle =
                    KeysetHandle.generateNew(
                            HybridKeyTemplates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM);
            KeysetHandle publicHandle = privateHandle.getPublicKeysetHandle();
            byte[] publicKey = writePublicKeyset(publicHandle);
            byte[] privateKey = writePrivateKeyset(privateHandle);
            try {
                return new DeviceKeyPair(
                        DEVICE_KEY_ALGORITHM, publicKey, privateKey, memoryProvider);
            } finally {
                Arrays.fill(publicKey, (byte) 0);
                Arrays.fill(privateKey, (byte) 0);
            }
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Could not generate device key pair", e);
        }
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

        byte[] nonce = new byte[aeadCipher.nonceSizeBytes()];
        random.nextBytes(nonce);
        byte[] ciphertext =
                withKeyBytes(key, keyBytes -> aeadCipher.encrypt(keyBytes, nonce, plaintext, aad));
        return new EncryptedEnvelope(
                1, aeadCipher.algorithm(), key.keyId(), nonce, aad, ciphertext, encryptedAt);
    }

    public byte @NonNull [] decrypt(
            @NonNull VaultKey key, @NonNull EncryptedEnvelope envelope, byte @NonNull [] aad) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(envelope, "envelope");
        Objects.requireNonNull(aad, "aad");
        if (envelope.version() != 1) {
            throw new CryptoException("Unsupported encrypted envelope version");
        }
        if (!key.keyId().equals(envelope.keyId())) {
            throw new CryptoException(
                    "Vault key id "
                            + key.keyId().value()
                            + " does not match encrypted envelope key id "
                            + envelope.keyId().value());
        }
        AeadCipher envelopeCipher = aeadCiphers.get(envelope.algorithm());
        if (envelopeCipher == null) {
            throw new CryptoException("Unsupported encrypted envelope algorithm");
        }
        if (!Arrays.equals(envelope.aad(), aad)) {
            throw new CryptoException("Encrypted envelope AAD does not match expected AAD");
        }
        return withKeyBytes(
                key,
                keyBytes ->
                        envelopeCipher.decrypt(
                                keyBytes, envelope.nonce(), envelope.ciphertext(), aad));
    }

    public byte @NonNull [] wrapVaultKey(
            @NonNull VaultKey vaultKey,
            char @NonNull [] masterPassword,
            byte @NonNull [] salt,
            int iterations) {
        return wrapVaultKey(vaultKey, masterPassword, salt, iterations, KDF_ALGORITHM);
    }

    public byte @NonNull [] wrapVaultKey(
            @NonNull VaultKey vaultKey,
            char @NonNull [] masterPassword,
            byte @NonNull [] salt,
            int iterations,
            @NonNull String kdfAlgorithm) {
        return wrapVaultKey(
                vaultKey, masterPassword, KdfParameters.pbkdf2(kdfAlgorithm, salt, iterations));
    }

    public byte @NonNull [] wrapVaultKey(
            @NonNull VaultKey vaultKey,
            char @NonNull [] masterPassword,
            @NonNull KdfParameters kdfParameters) {
        Objects.requireNonNull(vaultKey, "vaultKey");
        byte[] wrappingKey = deriveWrappingKey(masterPassword, kdfParameters);
        byte[] nonce = new byte[aeadCipher.nonceSizeBytes()];
        random.nextBytes(nonce);
        try {
            byte[] wrapped =
                    withKeyBytes(
                            vaultKey,
                            keyBytes ->
                                    aeadCipher.encrypt(
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
        return unwrapVaultKey(
                keyId, wrappedVaultKey, masterPassword, salt, iterations, KDF_ALGORITHM);
    }

    public @NonNull VaultKey unwrapVaultKey(
            @NonNull KeyId keyId,
            byte @NonNull [] wrappedVaultKey,
            char @NonNull [] masterPassword,
            byte @NonNull [] salt,
            int iterations,
            @NonNull String kdfAlgorithm) {
        return unwrapVaultKey(
                keyId,
                wrappedVaultKey,
                masterPassword,
                KdfParameters.pbkdf2(kdfAlgorithm, salt, iterations));
    }

    public @NonNull VaultKey unwrapVaultKey(
            @NonNull KeyId keyId,
            byte @NonNull [] wrappedVaultKey,
            char @NonNull [] masterPassword,
            @NonNull KdfParameters kdfParameters) {
        Objects.requireNonNull(keyId, "keyId");
        Objects.requireNonNull(wrappedVaultKey, "wrappedVaultKey");
        if (wrappedVaultKey.length <= aeadCipher.nonceSizeBytes()) {
            throw new CryptoException("Wrapped vault key is invalid");
        }

        byte[] wrappingKey = deriveWrappingKey(masterPassword, kdfParameters);
        byte[] nonce = Arrays.copyOfRange(wrappedVaultKey, 0, aeadCipher.nonceSizeBytes());
        byte[] ciphertext =
                Arrays.copyOfRange(
                        wrappedVaultKey, aeadCipher.nonceSizeBytes(), wrappedVaultKey.length);
        byte @Nullable [] opened = null;
        try {
            opened = aeadCipher.decrypt(wrappingKey, nonce, ciphertext, wrappingAad(keyId));
            return new VaultKey(keyId, opened, memoryProvider);
        } finally {
            Arrays.fill(wrappingKey, (byte) 0);
            Arrays.fill(nonce, (byte) 0);
            Arrays.fill(ciphertext, (byte) 0);
            if (opened != null) {
                Arrays.fill(opened, (byte) 0);
            }
        }
    }

    public byte @NonNull [] wrapVaultKeyForDevice(
            @NonNull VaultKey vaultKey,
            byte @NonNull [] devicePublicKey,
            byte @NonNull [] context) {
        Objects.requireNonNull(vaultKey, "vaultKey");
        Objects.requireNonNull(devicePublicKey, "devicePublicKey");
        Objects.requireNonNull(context, "context");
        try {
            registerHybridPrimitives();
            KeysetHandle publicHandle =
                    KeysetHandle.readNoSecret(JsonKeysetReader.withBytes(devicePublicKey));
            HybridEncrypt encrypt = publicHandle.getPrimitive(HybridEncrypt.class);
            return withKeyBytes(vaultKey, keyBytes -> encryptForDevice(encrypt, keyBytes, context));
        } catch (GeneralSecurityException | IOException e) {
            throw new CryptoException("Could not wrap vault key for device", e);
        }
    }

    public @NonNull VaultKey unwrapVaultKeyFromDevicePackage(
            @NonNull KeyId keyId,
            byte @NonNull [] encryptedVaultKey,
            byte @NonNull [] devicePrivateKey,
            byte @NonNull [] context) {
        Objects.requireNonNull(keyId, "keyId");
        Objects.requireNonNull(encryptedVaultKey, "encryptedVaultKey");
        Objects.requireNonNull(devicePrivateKey, "devicePrivateKey");
        Objects.requireNonNull(context, "context");
        byte @Nullable [] opened = null;
        try {
            registerHybridPrimitives();
            KeysetHandle privateHandle =
                    CleartextKeysetHandle.read(JsonKeysetReader.withBytes(devicePrivateKey));
            HybridDecrypt decrypt = privateHandle.getPrimitive(HybridDecrypt.class);
            opened = decrypt.decrypt(encryptedVaultKey, context);
            return new VaultKey(keyId, opened, memoryProvider);
        } catch (GeneralSecurityException | IOException e) {
            throw new CryptoException("Could not unwrap device vault key package", e);
        } finally {
            if (opened != null) {
                Arrays.fill(opened, (byte) 0);
            }
        }
    }

    public boolean supportsPasswordKdf(@NonNull String algorithm) {
        Objects.requireNonNull(algorithm, "algorithm");
        return passwordKeyDerivations.containsKey(algorithm);
    }

    private byte @NonNull [] deriveWrappingKey(
            char @NonNull [] masterPassword, @NonNull KdfParameters parameters) {
        Objects.requireNonNull(masterPassword, "masterPassword");
        Objects.requireNonNull(parameters, "parameters");
        PasswordKeyDerivation provider = passwordKeyDerivations.get(parameters.algorithm());
        if (provider == null) {
            throw new CryptoException("Unsupported vault key KDF algorithm");
        }
        char[] passwordCopy = Arrays.copyOf(masterPassword, masterPassword.length);
        byte[] result = null;
        try {
            result = provider.derive(passwordCopy, parameters, KEY_BYTES);
            if (result.length != KEY_BYTES) {
                throw new CryptoException("Password KDF returned an invalid key size");
            }
            byte[] output = result;
            result = null;
            return output;
        } finally {
            Arrays.fill(passwordCopy, '\0');
            if (result != null) {
                Arrays.fill(result, (byte) 0);
            }
        }
    }

    private byte @NonNull [] wrappingAad(@NonNull KeyId keyId) {
        return keyId.value().getBytes(StandardCharsets.UTF_8);
    }

    private byte @NonNull [] encryptForDevice(
            @NonNull HybridEncrypt encrypt, byte @NonNull [] keyBytes, byte @NonNull [] context) {
        try {
            return encrypt.encrypt(keyBytes, context);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Could not wrap vault key for device", e);
        }
    }

    private static void registerHybridPrimitives() {
        try {
            HybridConfig.register();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Could not register hybrid crypto primitives", e);
        }
    }

    private static @NonNull Map<String, AeadCipher> aeadCiphers(@NonNull AeadCipher primary) {
        Map<String, AeadCipher> ciphers = new LinkedHashMap<>();
        registerAeadCipher(ciphers, new TinkAesGcmCipher());
        registerAeadCipher(ciphers, new JdkChaCha20Poly1305Cipher());
        registerAeadCipher(ciphers, primary);
        return Map.copyOf(ciphers);
    }

    private static void registerAeadCipher(
            @NonNull Map<String, AeadCipher> ciphers, @NonNull AeadCipher cipher) {
        if (!CryptoAlgorithmRegistry.isApprovedAead(cipher.algorithm())) {
            throw new IllegalArgumentException("Unsupported AEAD cipher: " + cipher.algorithm());
        }
        ciphers.put(cipher.algorithm(), cipher);
    }

    private static @NonNull Collection<PasswordKeyDerivation> defaultPasswordKeyDerivations() {
        return java.util.List.of(
                new Pbkdf2KeyDerivation(CryptoAlgorithmRegistry.KDF_PBKDF2_HMAC_SHA256),
                new Pbkdf2KeyDerivation(CryptoAlgorithmRegistry.KDF_PBKDF2_HMAC_SHA512));
    }

    private static @NonNull Map<String, PasswordKeyDerivation> passwordKeyDerivations(
            @NonNull Collection<PasswordKeyDerivation> providers) {
        Objects.requireNonNull(providers, "passwordKeyDerivations");
        Map<String, PasswordKeyDerivation> registered = new LinkedHashMap<>();
        for (PasswordKeyDerivation provider : providers) {
            Objects.requireNonNull(provider, "passwordKeyDerivation");
            String algorithm = Objects.requireNonNull(provider.algorithm(), "provider algorithm");
            if (registered.putIfAbsent(algorithm, provider) != null) {
                throw new IllegalArgumentException("Duplicate password KDF provider: " + algorithm);
            }
        }
        return Map.copyOf(registered);
    }

    private static byte @NonNull [] writePublicKeyset(@NonNull KeysetHandle handle) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try {
            handle.writeNoSecret(JsonKeysetWriter.withOutputStream(output));
            return output.toByteArray();
        } catch (GeneralSecurityException | IOException e) {
            throw new CryptoException("Could not serialize public device key", e);
        }
    }

    private static byte @NonNull [] writePrivateKeyset(@NonNull KeysetHandle handle) {
        try (WipeableByteArrayOutputStream output = new WipeableByteArrayOutputStream()) {
            FilterOutputStream nonClosingOutput =
                    new FilterOutputStream(output) {
                        @Override
                        public void close() throws IOException {
                            flush();
                        }
                    };
            CleartextKeysetHandle.write(
                    handle, JsonKeysetWriter.withOutputStream(nonClosingOutput));
            return output.toByteArray();
        } catch (IOException e) {
            throw new CryptoException("Could not serialize private device key", e);
        }
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
