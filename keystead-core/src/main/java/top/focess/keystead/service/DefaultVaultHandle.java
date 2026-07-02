package top.focess.keystead.service;

import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.crypto.VaultKey;
import top.focess.keystead.model.*;
import top.focess.keystead.store.VaultStore;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Consumer;

final class DefaultVaultHandle implements VaultHandle {

    private final VaultId vaultId;
    private final VaultKey vaultKey;
    private final VaultStore store;
    private final DefaultCryptoService crypto;
    private final Clock clock;
    private boolean closed;

    DefaultVaultHandle(VaultId vaultId, VaultKey vaultKey, VaultStore store, DefaultCryptoService crypto, Clock clock) {
        this.vaultId = Objects.requireNonNull(vaultId, "vaultId");
        this.vaultKey = Objects.requireNonNull(vaultKey, "vaultKey");
        this.store = Objects.requireNonNull(store, "store");
        this.crypto = Objects.requireNonNull(crypto, "crypto");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public VaultId vaultId() {
        return vaultId;
    }

    @Override
    public SecretId saveLogin(Consumer<LoginDraft> draftConsumer) {
        Objects.requireNonNull(draftConsumer, "draftConsumer");
        requireOpen();

        LoginDraftImpl draft = new LoginDraftImpl();
        byte[] payload = null;
        try {
            draftConsumer.accept(draft);
            draft.validate();

            SecretId secretId = new SecretId(UUID.randomUUID());
            Instant now = clock.instant();
            SecretMetadata metadata = new SecretMetadata(
                secretId,
                SecretType.LOGIN_PASSWORD,
                draft.title(),
                draft.tags(),
                now,
                now,
                1L
            );
            payload = LoginPayloadCodec.encode(draft);
            byte[] aad = aad(metadata, 1L);
            try {
                EncryptedEnvelope envelope = crypto.encrypt(vaultKey, payload, aad, now);
                store.saveSecretRecord(new EncryptedSecretRecord(vaultId, metadata, envelope, 1L));
                return secretId;
            } finally {
                wipe(aad);
            }
        } finally {
            wipe(payload);
            draft.close();
        }
    }

    @Override
    public void withLogin(SecretId secretId, Consumer<LoginSecretView> viewConsumer) {
        Objects.requireNonNull(secretId, "secretId");
        Objects.requireNonNull(viewConsumer, "viewConsumer");
        requireOpen();

        EncryptedSecretRecord record = store.loadSecretRecord(vaultId, secretId)
            .orElseThrow(() -> new ValidationException("Login secret does not exist"));
        if (record.metadata().type() != SecretType.LOGIN_PASSWORD) {
            throw new ValidationException("Secret is not a login password");
        }

        byte[] aad = aad(record.metadata(), record.revision());
        byte[] payload = null;
        LoginSecretViewImpl view = null;
        try {
            payload = crypto.decrypt(vaultKey, record.payload(), aad);
            view = LoginPayloadCodec.decode(record.metadata(), payload);
            viewConsumer.accept(view);
        } finally {
            if (view != null) {
                view.close();
            }
            wipe(payload);
            wipe(aad);
        }
    }

    @Override
    public List<SecretMetadata> listSecrets() {
        requireOpen();
        return store.listMetadata(vaultId);
    }

    @Override
    public boolean isClosed() {
        return closed;
    }

    @Override
    public void close() {
        if (!closed) {
            vaultKey.close();
            closed = true;
        }
    }

    private byte[] aad(SecretMetadata metadata, long revision) {
        String value = vaultId.value() + "|" + metadata.id().value() + "|" + metadata.type().name() + "|" + revision;
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private void requireOpen() {
        if (closed) {
            throw new IllegalStateException("Vault handle is closed");
        }
    }

    private void wipe(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }
}
