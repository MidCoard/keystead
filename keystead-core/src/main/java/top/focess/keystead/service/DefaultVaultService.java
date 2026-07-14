package top.focess.keystead.service;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.crypto.CryptoAlgorithmRegistry;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.crypto.VaultKey;
import top.focess.keystead.model.KeyId;
import top.focess.keystead.model.SecretRecordAad;
import top.focess.keystead.model.SecurityLimits;
import top.focess.keystead.model.VaultHeader;
import top.focess.keystead.model.VaultId;
import top.focess.keystead.store.VaultKeyRotation;
import top.focess.keystead.store.VaultStore;

public final class DefaultVaultService implements VaultService {

    public static final String DEVICE_KEY_PACKAGE_ALGORITHM =
            CryptoAlgorithmRegistry.DEVICE_TINK_DEVICE_KEY_PACKAGE;

    private final VaultStore store;
    private final DefaultCryptoService crypto;
    private final Clock clock;

    public DefaultVaultService(@NonNull VaultStore store) {
        this(store, Clock.systemUTC());
    }

    public DefaultVaultService(@NonNull VaultStore store, @NonNull Clock clock) {
        this(store, new DefaultCryptoService(), clock);
    }

    public DefaultVaultService(
            @NonNull VaultStore store, @NonNull DefaultCryptoService crypto, @NonNull Clock clock) {
        this.store = Objects.requireNonNull(store, "store");
        this.crypto = Objects.requireNonNull(crypto, "crypto");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public @NonNull VaultHandle createVault(
            @NonNull CreateVaultRequest request, char @NonNull [] masterPassword) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(masterPassword, "masterPassword");

        VaultId vaultId = request.vaultId();
        KeyId keyId = new KeyId("vault-key-" + vaultId.value());
        VaultKey vaultKey = crypto.generateVaultKey(keyId);
        byte[] salt = crypto.randomSalt();
        byte[] wrappedVaultKey = null;
        try {
            wrappedVaultKey =
                    crypto.wrapVaultKey(
                            vaultKey,
                            masterPassword,
                            salt,
                            DefaultCryptoService.DEFAULT_KDF_ITERATIONS);
            Instant now = clock.instant();
            store.saveVaultHeader(
                    new VaultHeader(
                            vaultId,
                            1,
                            DefaultCryptoService.KDF_ALGORITHM,
                            salt,
                            DefaultCryptoService.DEFAULT_KDF_ITERATIONS,
                            keyId,
                            wrappedVaultKey,
                            now,
                            now));
            return new DefaultVaultHandle(vaultId, vaultKey, store, crypto, clock);
        } catch (RuntimeException e) {
            vaultKey.close();
            throw e;
        } finally {
            wipe(salt);
            wipe(wrappedVaultKey);
        }
    }

    @Override
    public @NonNull VaultHandle openVault(
            @NonNull VaultId vaultId, char @NonNull [] masterPassword) {
        Objects.requireNonNull(vaultId, "vaultId");
        Objects.requireNonNull(masterPassword, "masterPassword");

        VaultHeader header =
                store.loadVaultHeader(vaultId)
                        .orElseThrow(() -> new ValidationException("Vault does not exist"));
        if (!crypto.supportsPasswordKdf(header.kdfAlgorithm())) {
            throw new ValidationException("Vault is not protected by a master password header");
        }
        VaultKey vaultKey =
                crypto.unwrapVaultKey(
                        header.vaultKeyId(),
                        header.wrappedVaultKey(),
                        masterPassword,
                        header.kdfParameters());
        return new DefaultVaultHandle(vaultId, vaultKey, store, crypto, clock);
    }

    @Override
    public @NonNull VaultHandle rotateVaultKey(
            @NonNull VaultId vaultId, char @NonNull [] masterPassword) {
        Objects.requireNonNull(vaultId, "vaultId");
        Objects.requireNonNull(masterPassword, "masterPassword");
        VaultHeader previous =
                store.loadVaultHeader(vaultId)
                        .orElseThrow(() -> new ValidationException("Vault does not exist"));
        if (!crypto.supportsPasswordKdf(previous.kdfAlgorithm())) {
            throw new ValidationException("Vault is not protected by a master password header");
        }
        VaultKey oldKey =
                crypto.unwrapVaultKey(
                        previous.vaultKeyId(),
                        previous.wrappedVaultKey(),
                        masterPassword,
                        previous.kdfParameters());
        KeyId nextKeyId =
                new KeyId("vault-key-" + vaultId.value() + "-" + java.util.UUID.randomUUID());
        VaultKey nextKey = crypto.generateVaultKey(nextKeyId);
        byte[] wrapped = null;
        List<top.focess.keystead.model.EncryptedSecretRecord> rotated = new ArrayList<>();
        try {
            for (top.focess.keystead.model.EncryptedSecretRecord record :
                    store.listSecretRecords(vaultId)) {
                byte[] aad = SecretRecordAad.encode(vaultId, record.metadata(), record.revision());
                byte[] plaintext = null;
                try {
                    plaintext = crypto.decrypt(oldKey, record.payload(), aad);
                    rotated.add(
                            new top.focess.keystead.model.EncryptedSecretRecord(
                                    vaultId,
                                    record.metadata(),
                                    crypto.encrypt(nextKey, plaintext, aad, clock.instant()),
                                    record.revision()));
                } finally {
                    wipe(aad);
                    wipe(plaintext);
                }
            }
            wrapped = crypto.wrapVaultKey(nextKey, masterPassword, previous.kdfParameters());
            Instant now = clock.instant();
            store.commitVaultKeyRotation(
                    new VaultKeyRotation(
                            new VaultHeader(
                                    vaultId,
                                    previous.formatVersion(),
                                    previous.kdfParameters(),
                                    nextKeyId,
                                    wrapped,
                                    previous.createdAt(),
                                    now),
                            rotated));
            oldKey.close();
            return new DefaultVaultHandle(vaultId, nextKey, store, crypto, clock);
        } catch (RuntimeException e) {
            nextKey.close();
            throw e;
        } finally {
            oldKey.close();
            wipe(wrapped);
        }
    }

    @Override
    public @NonNull VaultHandle provisionVault(
            @NonNull VaultId vaultId,
            byte @NonNull [] encryptedVaultKey,
            byte @NonNull [] devicePrivateKey,
            byte @NonNull [] context) {
        Objects.requireNonNull(vaultId, "vaultId");
        Objects.requireNonNull(encryptedVaultKey, "encryptedVaultKey");
        Objects.requireNonNull(devicePrivateKey, "devicePrivateKey");
        Objects.requireNonNull(context, "context");

        return provisionVault(
                vaultId,
                defaultVaultKeyId(vaultId),
                DEVICE_KEY_PACKAGE_ALGORITHM,
                encryptedVaultKey,
                devicePrivateKey,
                context);
    }

    @Override
    public @NonNull VaultHandle provisionVault(
            @NonNull VaultId vaultId,
            @NonNull DeviceVaultKeyPackage keyPackage,
            byte @NonNull [] devicePrivateKey,
            byte @NonNull [] context) {
        Objects.requireNonNull(vaultId, "vaultId");
        Objects.requireNonNull(keyPackage, "keyPackage");
        Objects.requireNonNull(devicePrivateKey, "devicePrivateKey");
        Objects.requireNonNull(context, "context");
        byte @Nullable [] encryptedVaultKey = null;
        try {
            encryptedVaultKey = keyPackage.encryptedVaultKey();
            return provisionVault(
                    vaultId,
                    keyPackage.vaultKeyId(),
                    keyPackage.keyAlgorithm(),
                    encryptedVaultKey,
                    devicePrivateKey,
                    context);
        } finally {
            wipe(encryptedVaultKey);
        }
    }

    @Override
    public @NonNull VaultHandle provisionVault(
            @NonNull VaultId vaultId,
            @NonNull KeyId vaultKeyId,
            @NonNull String keyAlgorithm,
            byte @NonNull [] encryptedVaultKey,
            byte @NonNull [] devicePrivateKey,
            byte @NonNull [] context) {
        Objects.requireNonNull(vaultId, "vaultId");
        Objects.requireNonNull(vaultKeyId, "vaultKeyId");
        Objects.requireNonNull(keyAlgorithm, "keyAlgorithm");
        Objects.requireNonNull(encryptedVaultKey, "encryptedVaultKey");
        Objects.requireNonNull(devicePrivateKey, "devicePrivateKey");
        Objects.requireNonNull(context, "context");
        if (!CryptoAlgorithmRegistry.isApprovedDeviceKeyPackage(keyAlgorithm)) {
            throw new IllegalArgumentException("Device key package algorithm is unsupported");
        }
        if (encryptedVaultKey.length == 0) {
            throw new IllegalArgumentException("Encrypted vault key must not be empty");
        }
        if (encryptedVaultKey.length > SecurityLimits.MAX_WRAPPED_KEY_PACKAGE_BYTES) {
            throw new IllegalArgumentException("Encrypted vault key exceeds the size limit");
        }
        @Nullable VaultKey vaultKey = null;
        boolean transferred = false;
        try {
            vaultKey =
                    crypto.unwrapVaultKeyFromDevicePackage(
                            vaultKeyId, encryptedVaultKey, devicePrivateKey, context);
            Instant now = clock.instant();
            Instant createdAt =
                    store.loadVaultHeader(vaultId).map(VaultHeader::createdAt).orElse(now);
            store.saveVaultHeader(
                    new VaultHeader(
                            vaultId,
                            1,
                            keyAlgorithm,
                            new byte[0],
                            1,
                            vaultKeyId,
                            encryptedVaultKey,
                            createdAt,
                            now));
            VaultHandle handle = new DefaultVaultHandle(vaultId, vaultKey, store, crypto, clock);
            transferred = true;
            return handle;
        } finally {
            if (!transferred && vaultKey != null) {
                vaultKey.close();
            }
        }
    }

    @Override
    public @NonNull VaultHandle openVaultWithDeviceKey(
            @NonNull VaultId vaultId, byte @NonNull [] devicePrivateKey, byte @NonNull [] context) {
        Objects.requireNonNull(vaultId, "vaultId");
        Objects.requireNonNull(devicePrivateKey, "devicePrivateKey");
        Objects.requireNonNull(context, "context");

        VaultHeader header =
                store.loadVaultHeader(vaultId)
                        .orElseThrow(() -> new ValidationException("Vault does not exist"));
        if (!DEVICE_KEY_PACKAGE_ALGORITHM.equals(header.kdfAlgorithm())) {
            throw new ValidationException("Vault is not protected by a device key package");
        }
        VaultKey vaultKey =
                crypto.unwrapVaultKeyFromDevicePackage(
                        header.vaultKeyId(), header.wrappedVaultKey(), devicePrivateKey, context);
        return new DefaultVaultHandle(vaultId, vaultKey, store, crypto, clock);
    }

    private @NonNull KeyId defaultVaultKeyId(@NonNull VaultId vaultId) {
        return new KeyId("vault-key-" + vaultId.value());
    }

    private void wipe(byte @Nullable [] value) {
        if (value != null) {
            java.util.Arrays.fill(value, (byte) 0);
        }
    }
}
