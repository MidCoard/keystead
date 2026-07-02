package top.focess.keystead.service;

import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.crypto.VaultKey;
import top.focess.keystead.model.KeyId;
import top.focess.keystead.model.VaultHeader;
import top.focess.keystead.model.VaultId;
import top.focess.keystead.store.VaultStore;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;

public final class DefaultVaultService implements VaultService {

    private final VaultStore store;
    private final DefaultCryptoService crypto;
    private final Clock clock;

    public DefaultVaultService(VaultStore store) {
        this(store, Clock.systemUTC());
    }

    public DefaultVaultService(VaultStore store, Clock clock) {
        this(store, new DefaultCryptoService(), clock);
    }

    public DefaultVaultService(VaultStore store, DefaultCryptoService crypto, Clock clock) {
        this.store = Objects.requireNonNull(store, "store");
        this.crypto = Objects.requireNonNull(crypto, "crypto");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public VaultHandle createVault(CreateVaultRequest request, char[] masterPassword) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(masterPassword, "masterPassword");

        VaultId vaultId = request.vaultId();
        KeyId keyId = new KeyId("vault-key-" + vaultId.value());
        VaultKey vaultKey = crypto.generateVaultKey(keyId);
        byte[] salt = crypto.randomSalt();
        byte[] wrappedVaultKey = null;
        try {
            wrappedVaultKey = crypto.wrapVaultKey(vaultKey, masterPassword, salt, DefaultCryptoService.DEFAULT_KDF_ITERATIONS);
            Instant now = clock.instant();
            store.saveVaultHeader(new VaultHeader(
                vaultId,
                1,
                DefaultCryptoService.KDF_ALGORITHM,
                salt,
                DefaultCryptoService.DEFAULT_KDF_ITERATIONS,
                keyId,
                wrappedVaultKey,
                now,
                now
            ));
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
    public VaultHandle openVault(VaultId vaultId, char[] masterPassword) {
        Objects.requireNonNull(vaultId, "vaultId");
        Objects.requireNonNull(masterPassword, "masterPassword");

        VaultHeader header = store.loadVaultHeader(vaultId)
            .orElseThrow(() -> new ValidationException("Vault does not exist"));
        VaultKey vaultKey = crypto.unwrapVaultKey(
            header.vaultKeyId(),
            header.wrappedVaultKey(),
            masterPassword,
            header.kdfSalt(),
            header.kdfIterations()
        );
        return new DefaultVaultHandle(vaultId, vaultKey, store, crypto, clock);
    }

    private void wipe(byte[] value) {
        if (value != null) {
            java.util.Arrays.fill(value, (byte) 0);
        }
    }
}
