package top.focess.keystead.service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.crypto.CryptoAlgorithmRegistry;
import top.focess.keystead.crypto.CryptoException;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.crypto.KdfParameters;
import top.focess.keystead.crypto.VaultKey;
import top.focess.keystead.memory.Wipe;
import top.focess.keystead.model.EncryptedSecretRecord;
import top.focess.keystead.model.KeyId;
import top.focess.keystead.model.KeySlot;
import top.focess.keystead.model.SecretRecordAad;
import top.focess.keystead.model.SlotType;
import top.focess.keystead.model.VaultFingerprint;
import top.focess.keystead.model.VaultHeader;
import top.focess.keystead.store.OneFileVaultStore;
import top.focess.keystead.store.VaultFileFormat;
import top.focess.keystead.store.VaultKeyRotation;

/**
 * Default {@link VaultService} implementation backed by {@link OneFileVaultStore} factories.
 *
 * <p>Each create/open/provision call produces a fresh, single-file store bound to one vault file.
 * The service holds only the cryptographic service, the clock, and the handle factory; it owns no
 * long-lived store. Vault-key rotation re-wraps the passphrase slot under the same Argon2id
 * parameters so the fingerprint is unchanged.
 */
public final class DefaultVaultService implements VaultService {

    /** Device key-package algorithm used by this service. */
    public static final @NonNull String DEVICE_KEY_PACKAGE_ALGORITHM =
            CryptoAlgorithmRegistry.DEVICE_TINK_DEVICE_KEY_PACKAGE;

    private final DefaultCryptoService crypto;
    private final Clock clock;
    private final VaultHandleFactory handleFactory;

    /** Creates a service with a default crypto service and system clock. */
    public DefaultVaultService() {
        this(new DefaultCryptoService(), Clock.systemUTC());
    }

    /**
     * Creates a service with the supplied crypto service and clock.
     *
     * @param crypto the cryptographic service
     * @param clock the clock for timestamps
     */
    public DefaultVaultService(@NonNull DefaultCryptoService crypto, @NonNull Clock clock) {
        this(crypto, clock, DefaultVaultHandle::new);
    }

    DefaultVaultService(
            @NonNull DefaultCryptoService crypto,
            @NonNull Clock clock,
            @NonNull VaultHandleFactory handleFactory) {
        this.crypto = Objects.requireNonNull(crypto, "crypto");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.handleFactory = Objects.requireNonNull(handleFactory, "handleFactory");
    }

    @Override
    public @NonNull VaultHandle createVault(
            @NonNull CreateVaultRequest request, char @NonNull [] passphrase) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(passphrase, "passphrase");
        OneFileVaultStore store =
                OneFileVaultStore.create(crypto, request.file(), passphrase, clock);
        boolean storeTransferred = false;
        try {
            VaultHandle handle = handleFactory.create(store);
            storeTransferred = true;
            return handle;
        } finally {
            if (!storeTransferred) {
                store.close();
            }
        }
    }

    @Override
    public @NonNull VaultHandle openVault(@NonNull Path file, char @NonNull [] passphrase) {
        Objects.requireNonNull(file, "file");
        Objects.requireNonNull(passphrase, "passphrase");
        OneFileVaultStore store = OneFileVaultStore.open(crypto, file, passphrase, clock);
        boolean storeTransferred = false;
        try {
            VaultHandle handle = handleFactory.create(store);
            storeTransferred = true;
            return handle;
        } finally {
            if (!storeTransferred) {
                store.close();
            }
        }
    }

    @Override
    public @NonNull VaultHandle rotateVaultKey(@NonNull Path file, char @NonNull [] passphrase) {
        Objects.requireNonNull(file, "file");
        Objects.requireNonNull(passphrase, "passphrase");
        OneFileVaultStore store = OneFileVaultStore.open(crypto, file, passphrase, clock);
        boolean storeTransferred = false;
        @Nullable VaultKey nextDek = null;
        byte @Nullable [] wrapped = null;
        try {
            VaultHeader previousHeader = store.header();
            KeySlot passSlot =
                    previousHeader
                            .firstPassphraseSlot()
                            .orElseThrow(
                                    () ->
                                            new ValidationException(
                                                    "Vault has no passphrase key slot"));
            KdfParameters kdf = passSlot.requireKdfParameters();
            VaultFingerprint fingerprint = store.vaultFingerprint();
            nextDek = crypto.generateVaultKey(new KeyId("vault-" + UUID.randomUUID()));
            List<EncryptedSecretRecord> rotated = new ArrayList<>();
            for (EncryptedSecretRecord record : store.listSecretRecords()) {
                byte[] aad =
                        SecretRecordAad.encode(fingerprint, record.metadata(), record.revision());
                byte @Nullable [] plaintext = null;
                try {
                    plaintext = crypto.decrypt(store.vaultKey(), record.payload(), aad);
                    rotated.add(
                            new EncryptedSecretRecord(
                                    record.metadata(),
                                    crypto.encrypt(nextDek, plaintext, aad, clock.instant()),
                                    record.revision()));
                } finally {
                    Wipe.wipe(aad);
                    Wipe.wipe(plaintext);
                }
            }
            wrapped = crypto.wrapVaultKey(nextDek, passphrase, kdf);
            Instant now = clock.instant();
            KeySlot newPassSlot =
                    new KeySlot(SlotType.PASSPHRASE, new KeyId("passphrase"), kdf, wrapped);
            VaultHeader newHeader =
                    previousHeader.withVaultKey(nextDek.keyId(), List.of(newPassSlot), now);
            store.commitVaultKeyRotation(new VaultKeyRotation(newHeader, rotated, nextDek));
            nextDek = null;
            VaultHandle handle = handleFactory.create(store);
            storeTransferred = true;
            return handle;
        } finally {
            if (!storeTransferred) {
                store.close();
            }
            if (nextDek != null) {
                nextDek.close();
            }
            Wipe.wipe(wrapped);
        }
    }

    @Override
    public @NonNull VaultHandle provisionVault(
            @NonNull Path file,
            @NonNull DeviceVaultKeyPackage keyPackage,
            byte @NonNull [] devicePrivateKey,
            byte @NonNull [] context) {
        Objects.requireNonNull(file, "file");
        Objects.requireNonNull(keyPackage, "keyPackage");
        Objects.requireNonNull(devicePrivateKey, "devicePrivateKey");
        Objects.requireNonNull(context, "context");
        byte @Nullable [] wrapped = null;
        try {
            wrapped = keyPackage.encryptedVaultKey();
            return provisionVault(
                    file,
                    keyPackage.fingerprint(),
                    keyPackage.vaultKeyId(),
                    wrapped,
                    devicePrivateKey,
                    context,
                    SlotType.DEVICE);
        } finally {
            Wipe.wipe(wrapped);
        }
    }

    @Override
    public @NonNull VaultHandle provisionVaultWithRecoveryKey(
            @NonNull Path file,
            @NonNull VaultFingerprint fingerprint,
            @NonNull KeyId vaultKeyId,
            byte @NonNull [] encryptedVaultKey,
            byte @NonNull [] recoveryPrivateKey,
            byte @NonNull [] context) {
        Objects.requireNonNull(file, "file");
        Objects.requireNonNull(fingerprint, "fingerprint");
        Objects.requireNonNull(vaultKeyId, "vaultKeyId");
        Objects.requireNonNull(encryptedVaultKey, "encryptedVaultKey");
        Objects.requireNonNull(recoveryPrivateKey, "recoveryPrivateKey");
        Objects.requireNonNull(context, "context");
        return provisionVault(
                file,
                fingerprint,
                vaultKeyId,
                encryptedVaultKey,
                recoveryPrivateKey,
                context,
                SlotType.RECOVERY);
    }

    private @NonNull VaultHandle provisionVault(
            @NonNull Path file,
            @NonNull VaultFingerprint fingerprint,
            @NonNull KeyId vaultKeyId,
            byte @NonNull [] encryptedVaultKey,
            byte @NonNull [] privateKey,
            byte @NonNull [] context,
            @NonNull SlotType slotType) {
        @Nullable VaultKey dek = null;
        boolean storeTransferred = false;
        try {
            dek =
                    crypto.unwrapVaultKeyFromDevicePackage(
                            vaultKeyId, encryptedVaultKey, privateKey, context);
            Instant now = clock.instant();
            KeySlot slot =
                    new KeySlot(
                            slotType,
                            new KeyId(slotType.name().toLowerCase() + "-" + UUID.randomUUID()),
                            null,
                            encryptedVaultKey);
            VaultHeader header =
                    new VaultHeader(
                            VaultFileFormat.FORMAT_VERSION,
                            fingerprint,
                            dek.keyId(),
                            List.of(slot),
                            now,
                            now);
            OneFileVaultStore store =
                    OneFileVaultStore.createWithVaultKey(crypto, file, dek, header, clock);
            dek = null;
            VaultHandle handle = handleFactory.create(store);
            storeTransferred = true;
            return handle;
        } finally {
            if (!storeTransferred && dek != null) {
                dek.close();
            }
        }
    }

    @Override
    public @NonNull VaultHandle openVaultWithDeviceKey(
            @NonNull Path file, byte @NonNull [] devicePrivateKey, byte @NonNull [] context) {
        Objects.requireNonNull(file, "file");
        Objects.requireNonNull(devicePrivateKey, "devicePrivateKey");
        Objects.requireNonNull(context, "context");
        VaultHeader header = VaultFileFormat.readHeader(readVaultFile(file));
        @Nullable VaultKey dek = null;
        for (KeySlot slot : header.slots()) {
            if (slot.slotType() != SlotType.DEVICE) {
                continue;
            }
            byte @Nullable [] wrapped = null;
            try {
                wrapped = slot.wrappedVaultKey();
                try {
                    dek =
                            crypto.unwrapVaultKeyFromDevicePackage(
                                    header.vaultKeyId(), wrapped, devicePrivateKey, context);
                    break;
                } catch (CryptoException ignored) {
                    // This device slot does not unwrap under the supplied key; try the next.
                }
            } finally {
                Wipe.wipe(wrapped);
            }
        }
        if (dek == null) {
            throw new ValidationException("Vault is not protected by this device key");
        }
        boolean storeTransferred = false;
        @Nullable OneFileVaultStore store = null;
        try {
            store = OneFileVaultStore.openWithVaultKey(crypto, file, dek, clock);
            dek = null;
            VaultHandle handle = handleFactory.create(store);
            storeTransferred = true;
            return handle;
        } finally {
            if (!storeTransferred) {
                if (store != null) {
                    store.close();
                } else if (dek != null) {
                    dek.close();
                }
            }
        }
    }

    private byte @NonNull [] readVaultFile(@NonNull Path file) {
        try {
            return Files.readAllBytes(file);
        } catch (NoSuchFileException e) {
            throw new ValidationException("Vault file does not exist: " + file);
        } catch (IOException e) {
            throw new top.focess.keystead.store.StoreException(
                    "Could not read vault file: " + file, e);
        }
    }

    @FunctionalInterface
    interface VaultHandleFactory {

        @NonNull VaultHandle create(@NonNull OneFileVaultStore store);
    }
}
