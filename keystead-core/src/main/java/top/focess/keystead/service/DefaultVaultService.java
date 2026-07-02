package top.focess.keystead.service;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.crypto.VaultKey;
import top.focess.keystead.model.KeyId;
import top.focess.keystead.model.VaultHeader;
import top.focess.keystead.model.VaultId;
import top.focess.keystead.store.VaultStore;

public final class DefaultVaultService implements VaultService {

    public static final String DEVICE_KEY_PACKAGE_ALGORITHM = "TINK_DEVICE_KEY_PACKAGE";

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
        if (!DefaultCryptoService.KDF_ALGORITHM.equals(header.kdfAlgorithm())) {
            throw new ValidationException("Vault is not protected by a master password header");
        }
        VaultKey vaultKey =
                crypto.unwrapVaultKey(
                        header.vaultKeyId(),
                        header.wrappedVaultKey(),
                        masterPassword,
                        header.kdfSalt(),
                        header.kdfIterations());
        return new DefaultVaultHandle(vaultId, vaultKey, store, crypto, clock);
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

        KeyId keyId = defaultVaultKeyId(vaultId);
        VaultKey vaultKey =
                crypto.unwrapVaultKeyFromDevicePackage(
                        keyId, encryptedVaultKey, devicePrivateKey, context);
        try {
            Instant now = clock.instant();
            Instant createdAt =
                    store.loadVaultHeader(vaultId).map(VaultHeader::createdAt).orElse(now);
            store.saveVaultHeader(
                    new VaultHeader(
                            vaultId,
                            1,
                            DEVICE_KEY_PACKAGE_ALGORITHM,
                            new byte[0],
                            1,
                            keyId,
                            encryptedVaultKey,
                            createdAt,
                            now));
            return new DefaultVaultHandle(vaultId, vaultKey, store, crypto, clock);
        } catch (RuntimeException e) {
            vaultKey.close();
            throw e;
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
