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
import top.focess.keystead.memory.Wipe;
import top.focess.keystead.memory.WipeableByteArrayOutputStream;
import top.focess.keystead.model.EncryptedEnvelope;
import top.focess.keystead.model.KeyId;

/**
 * Default cryptographic service: derives and wraps vault keys, encrypts and decrypts secret
 * payloads with authenticated encryption, and wraps or unwraps vault keys for devices. The default
 * configuration uses PBKDF2-HMAC-SHA-256 (120,000 iterations) and AES-256-GCM.
 */
public final class DefaultCryptoService {

    /** Approved AEAD algorithm used for secret payloads. */
    public static final @NonNull String PAYLOAD_ALGORITHM =
            CryptoAlgorithmRegistry.AEAD_AES_256_GCM;

    /** Approved device key-package algorithm used for device wrapping. */
    public static final @NonNull String DEVICE_KEY_ALGORITHM =
            CryptoAlgorithmRegistry.DEVICE_TINK_ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM;

    /** Approved KDF algorithm used to wrap vault keys from a master password. */
    public static final @NonNull String KDF_ALGORITHM =
            CryptoAlgorithmRegistry.KDF_PBKDF2_HMAC_SHA256;

    /** Default PBKDF2 iteration count. */
    public static final int DEFAULT_KDF_ITERATIONS = 120_000;

    private static final int KEY_BYTES = 32;
    private static final int SALT_BYTES = 16;

    private final SecureRandom random;
    private final AeadCipher aeadCipher;
    private final SecretMemoryProvider memoryProvider;
    private final Map<String, AeadCipher> aeadCiphers;
    private final Map<String, PasswordKeyDerivation> passwordKeyDerivations;

    /** Creates a service with a default secure random and AES-256-GCM cipher. */
    public DefaultCryptoService() {
        this(new SecureRandom());
    }

    /**
     * Creates a service with the supplied secure random and AES-256-GCM cipher.
     *
     * @param random the secure random source
     */
    public DefaultCryptoService(@NonNull SecureRandom random) {
        this(random, new TinkAesGcmCipher());
    }

    /**
     * Creates a service with the supplied secure random and primary AEAD cipher.
     *
     * @param random the secure random source
     * @param aeadCipher the primary AEAD cipher
     */
    public DefaultCryptoService(@NonNull SecureRandom random, @NonNull AeadCipher aeadCipher) {
        this(random, aeadCipher, SecretMemoryProvider.systemDefault());
    }

    /**
     * Creates a service with an explicit secret-memory provider for key material.
     *
     * @param random the secure random source
     * @param aeadCipher the primary AEAD cipher
     * @param memoryProvider the provider used to protect key material
     */
    public DefaultCryptoService(
            @NonNull SecureRandom random,
            @NonNull AeadCipher aeadCipher,
            @NonNull SecretMemoryProvider memoryProvider) {
        this(random, aeadCipher, memoryProvider, defaultPasswordKeyDerivations());
    }

    /**
     * Creates a service with explicit password KDF implementations.
     *
     * @param random the secure random source
     * @param aeadCipher the primary AEAD cipher
     * @param memoryProvider the provider used to protect key material
     * @param passwordKeyDerivations the supported password key-derivation functions
     */
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

    /**
     * Generates a fresh random vault key with the given id.
     *
     * @param keyId the new key id
     * @return the generated vault key
     */
    public @NonNull VaultKey generateVaultKey(@NonNull KeyId keyId) {
        byte[] keyBytes = new byte[KEY_BYTES];
        random.nextBytes(keyBytes);
        try {
            return new VaultKey(keyId, keyBytes, memoryProvider);
        } finally {
            Arrays.fill(keyBytes, (byte) 0);
        }
    }

    /**
     * Generates a fresh random KDF salt.
     *
     * @return the salt
     */
    public byte @NonNull [] randomSalt() {
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        return salt;
    }

    /**
     * Generates a new device ECIES key pair.
     *
     * @return the device key pair
     */
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

    /**
     * Encrypts plaintext as an envelope authenticated by the vault id, metadata, and revision.
     *
     * @param key the vault key
     * @param plaintext the plaintext
     * @param aad the additional authenticated data
     * @param encryptedAt the encryption timestamp
     * @return the encrypted envelope
     */
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

    /**
     * Decrypts an envelope, verifying the key id and AAD match.
     *
     * @param key the vault key
     * @param envelope the encrypted envelope
     * @param aad the additional authenticated data
     * @return the plaintext
     */
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

    /**
     * Wraps a vault key with a password-derived key and the default KDF.
     *
     * @param vaultKey the vault key
     * @param masterPassword caller-owned master password
     * @param salt the KDF salt
     * @param iterations the KDF iterations
     * @return the wrapped vault key bytes
     */
    public byte @NonNull [] wrapVaultKey(
            @NonNull VaultKey vaultKey,
            char @NonNull [] masterPassword,
            byte @NonNull [] salt,
            int iterations) {
        return wrapVaultKey(vaultKey, masterPassword, salt, iterations, KDF_ALGORITHM);
    }

    /**
     * Wraps a vault key with a password-derived key and the named KDF.
     *
     * @param vaultKey the vault key
     * @param masterPassword caller-owned master password
     * @param salt the KDF salt
     * @param iterations the KDF iterations
     * @param kdfAlgorithm the KDF algorithm
     * @return the wrapped vault key bytes
     */
    public byte @NonNull [] wrapVaultKey(
            @NonNull VaultKey vaultKey,
            char @NonNull [] masterPassword,
            byte @NonNull [] salt,
            int iterations,
            @NonNull String kdfAlgorithm) {
        return wrapVaultKey(
                vaultKey, masterPassword, KdfParameters.pbkdf2(kdfAlgorithm, salt, iterations));
    }

    /**
     * Wraps a vault key with a key derived from a master password.
     *
     * @param vaultKey the vault key to wrap
     * @param masterPassword caller-owned master password
     * @param kdfParameters the password KDF parameters
     * @return the wrapped vault key bytes, including the nonce prefix
     */
    public byte @NonNull [] wrapVaultKey(
            @NonNull VaultKey vaultKey,
            char @NonNull [] masterPassword,
            @NonNull KdfParameters kdfParameters) {
        Objects.requireNonNull(vaultKey, "vaultKey");
        byte @Nullable [] wrappingKey = null;
        byte @Nullable [] nonce = null;
        byte @Nullable [] wrapped = null;
        byte @Nullable [] output = null;
        try {
            wrappingKey = deriveWrappingKey(masterPassword, kdfParameters);
            nonce = new byte[aeadCipher.nonceSizeBytes()];
            random.nextBytes(nonce);
            byte[] wrappingKeyForCipher = wrappingKey;
            byte[] nonceForCipher = nonce;
            wrapped =
                    withKeyBytes(
                            vaultKey,
                            keyBytes ->
                                    aeadCipher.encrypt(
                                            wrappingKeyForCipher,
                                            nonceForCipher,
                                            keyBytes,
                                            wrappingAad(vaultKey.keyId())));
            output = new byte[nonce.length + wrapped.length];
            System.arraycopy(nonce, 0, output, 0, nonce.length);
            System.arraycopy(wrapped, 0, output, nonce.length, wrapped.length);
            byte[] result = output;
            output = null;
            return result;
        } finally {
            Wipe.wipe(wrappingKey);
            Wipe.wipe(nonce);
            Wipe.wipe(wrapped);
            Wipe.wipe(output);
        }
    }

    /**
     * Unwraps a vault key with a password-derived key and the default KDF.
     *
     * @param keyId the key id
     * @param wrappedVaultKey the wrapped bytes
     * @param masterPassword caller-owned master password
     * @param salt the KDF salt
     * @param iterations the KDF iterations
     * @return the unwrapped vault key
     */
    public @NonNull VaultKey unwrapVaultKey(
            @NonNull KeyId keyId,
            byte @NonNull [] wrappedVaultKey,
            char @NonNull [] masterPassword,
            byte @NonNull [] salt,
            int iterations) {
        return unwrapVaultKey(
                keyId, wrappedVaultKey, masterPassword, salt, iterations, KDF_ALGORITHM);
    }

    /**
     * Unwraps a vault key with a password-derived key and the named KDF.
     *
     * @param keyId the key id
     * @param wrappedVaultKey the wrapped bytes
     * @param masterPassword caller-owned master password
     * @param salt the KDF salt
     * @param iterations the KDF iterations
     * @param kdfAlgorithm the KDF algorithm
     * @return the unwrapped vault key
     */
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

    /**
     * Unwraps a password-wrapped vault key.
     *
     * @param keyId the identifier of the vault key generation
     * @param wrappedVaultKey the wrapped vault key bytes, including the nonce prefix
     * @param masterPassword caller-owned master password
     * @param kdfParameters the password KDF parameters used at wrap time
     * @return the unwrapped vault key; the caller must close it
     */
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

        byte @Nullable [] wrappingKey = null;
        byte @Nullable [] nonce = null;
        byte @Nullable [] ciphertext = null;
        byte @Nullable [] opened = null;
        try {
            wrappingKey = deriveWrappingKey(masterPassword, kdfParameters);
            nonce = Arrays.copyOfRange(wrappedVaultKey, 0, aeadCipher.nonceSizeBytes());
            ciphertext =
                    Arrays.copyOfRange(
                            wrappedVaultKey, aeadCipher.nonceSizeBytes(), wrappedVaultKey.length);
            opened = aeadCipher.decrypt(wrappingKey, nonce, ciphertext, wrappingAad(keyId));
            return new VaultKey(keyId, opened, memoryProvider);
        } finally {
            Wipe.wipe(wrappingKey);
            Wipe.wipe(nonce);
            Wipe.wipe(ciphertext);
            Wipe.wipe(opened);
        }
    }

    /**
     * Wraps a vault key for a device's public key.
     *
     * @param vaultKey the vault key
     * @param devicePublicKey the recipient device public key
     * @param context the binding context
     * @return the wrapped vault key bytes
     */
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

    /**
     * Unwraps a vault key from a device-wrapped package using the device private key.
     *
     * @param keyId the key id
     * @param encryptedVaultKey the device-wrapped bytes
     * @param devicePrivateKey caller-owned device private key
     * @param context the binding context
     * @return the unwrapped vault key
     */
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

    /**
     * Returns whether a password KDF algorithm is supported.
     *
     * @param algorithm the KDF algorithm name
     * @return whether the algorithm has a registered implementation
     */
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
