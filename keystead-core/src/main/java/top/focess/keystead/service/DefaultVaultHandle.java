package top.focess.keystead.service;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Consumer;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.crypto.VaultKey;
import top.focess.keystead.model.*;
import top.focess.keystead.store.VaultStore;

final class DefaultVaultHandle implements VaultHandle {

    private final VaultId vaultId;
    private final VaultKey vaultKey;
    private final VaultStore store;
    private final DefaultCryptoService crypto;
    private final Clock clock;
    private boolean closed;

    DefaultVaultHandle(
            @NonNull VaultId vaultId,
            @NonNull VaultKey vaultKey,
            @NonNull VaultStore store,
            @NonNull DefaultCryptoService crypto,
            @NonNull Clock clock) {
        this.vaultId = Objects.requireNonNull(vaultId, "vaultId");
        this.vaultKey = Objects.requireNonNull(vaultKey, "vaultKey");
        this.store = Objects.requireNonNull(store, "store");
        this.crypto = Objects.requireNonNull(crypto, "crypto");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public @NonNull VaultId vaultId() {
        return vaultId;
    }

    @Override
    public @NonNull SecretId saveLogin(@NonNull Consumer<LoginDraft> draftConsumer) {
        Objects.requireNonNull(draftConsumer, "draftConsumer");
        requireOpen();

        LoginDraftImpl draft = new LoginDraftImpl();
        byte @Nullable [] payload = null;
        try {
            draftConsumer.accept(draft);
            draft.validate();

            SecretId secretId = new SecretId(UUID.randomUUID());
            Instant now = clock.instant();
            SecretMetadata metadata =
                    new SecretMetadata(
                            secretId,
                            SecretType.LOGIN_PASSWORD,
                            new SecretProfile(
                                    draft.title(),
                                    draft.classification(),
                                    draft.tags(),
                                    draft.attributes()),
                            now,
                            now,
                            1L);
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
    public void withLogin(
            @NonNull SecretId secretId, @NonNull Consumer<LoginSecretView> viewConsumer) {
        Objects.requireNonNull(secretId, "secretId");
        Objects.requireNonNull(viewConsumer, "viewConsumer");
        requireOpen();

        EncryptedSecretRecord record =
                store.loadSecretRecord(vaultId, secretId)
                        .orElseThrow(() -> new ValidationException("Login secret does not exist"));
        if (record.metadata().type() != SecretType.LOGIN_PASSWORD) {
            throw new ValidationException("Secret is not a login password");
        }

        byte[] aad = aad(record.metadata(), record.revision());
        byte @Nullable [] payload = null;
        @Nullable LoginSecretViewImpl view = null;
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
    public @NonNull SecretId saveSecureNote(@NonNull Consumer<SecureNoteDraft> draftConsumer) {
        Objects.requireNonNull(draftConsumer, "draftConsumer");
        requireOpen();

        SecureNoteDraftImpl draft = new SecureNoteDraftImpl();
        byte @Nullable [] payload = null;
        try {
            draftConsumer.accept(draft);
            draft.validate();

            SecretId secretId = new SecretId(UUID.randomUUID());
            Instant now = clock.instant();
            SecretMetadata metadata =
                    new SecretMetadata(
                            secretId,
                            SecretType.SECURE_NOTE,
                            new SecretProfile(
                                    draft.title(),
                                    draft.classification(),
                                    draft.tags(),
                                    draft.attributes()),
                            now,
                            now,
                            1L);
            payload = SecureNotePayloadCodec.encode(draft);
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
    public void withSecureNote(
            @NonNull SecretId secretId, @NonNull Consumer<SecureNoteView> viewConsumer) {
        Objects.requireNonNull(secretId, "secretId");
        Objects.requireNonNull(viewConsumer, "viewConsumer");
        requireOpen();

        EncryptedSecretRecord record =
                store.loadSecretRecord(vaultId, secretId)
                        .orElseThrow(() -> new ValidationException("Secure note does not exist"));
        if (record.metadata().type() != SecretType.SECURE_NOTE) {
            throw new ValidationException("Secret is not a secure note");
        }

        byte[] aad = aad(record.metadata(), record.revision());
        byte @Nullable [] payload = null;
        @Nullable SecureNoteViewImpl view = null;
        try {
            payload = crypto.decrypt(vaultKey, record.payload(), aad);
            view = SecureNotePayloadCodec.decode(record.metadata(), payload);
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
    public void deleteSecret(@NonNull SecretId secretId) {
        Objects.requireNonNull(secretId, "secretId");
        requireOpen();
        store.deleteSecretRecord(vaultId, secretId);
    }

    @Override
    public @NonNull List<SecretMetadata> listSecrets() {
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

    private byte @NonNull [] aad(@NonNull SecretMetadata metadata, long revision) {
        StringBuilder value = new StringBuilder();
        appendAad(value, "keystead-secret-record-v2");
        appendAad(value, vaultId.value().toString());
        appendAad(value, metadata.id().value().toString());
        appendAad(value, metadata.type().name());
        appendAad(value, metadata.title());
        appendAad(value, nullableAad(metadata.classification().category()));
        appendAad(value, nullableAad(metadata.classification().provider()));
        appendAad(value, nullableAad(metadata.classification().account()));
        appendAad(value, Integer.toString(metadata.classification().labels().size()));
        metadata.classification().labels().stream()
                .sorted()
                .forEach(label -> appendAad(value, label));
        appendAad(value, Integer.toString(metadata.tags().size()));
        metadata.tags().stream().sorted().forEach(tag -> appendAad(value, tag));
        appendAad(value, Integer.toString(metadata.profile().attributes().size()));
        metadata.profile().attributes().entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(
                        entry -> {
                            appendAad(value, entry.getKey());
                            appendAad(value, entry.getValue());
                        });
        appendAad(value, metadata.createdAt().toString());
        appendAad(value, metadata.updatedAt().toString());
        appendAad(value, Long.toString(metadata.revision()));
        appendAad(value, Long.toString(revision));
        return value.toString().getBytes(StandardCharsets.UTF_8);
    }

    private void appendAad(@NonNull StringBuilder builder, @NonNull String value) {
        builder.append(value.length()).append(':').append(value).append('|');
    }

    private @NonNull String nullableAad(@Nullable String value) {
        return value == null ? "" : value;
    }

    private void requireOpen() {
        if (closed) {
            throw new IllegalStateException("Vault handle is closed");
        }
    }

    private void wipe(byte @Nullable [] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }
}
