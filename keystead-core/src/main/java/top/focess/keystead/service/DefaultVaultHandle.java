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
            byte[] encodedPayload = LoginPayloadCodec.encode(draft);
            payload = encodedPayload;
            store.commitMutation(
                    vaultId,
                    revision -> {
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
                                        revision);
                        byte[] aad = aad(metadata, revision);
                        try {
                            EncryptedEnvelope envelope =
                                    crypto.encrypt(vaultKey, encodedPayload, aad, now);
                            store.saveSecretRecord(
                                    new EncryptedSecretRecord(
                                            vaultId, metadata, envelope, revision));
                        } finally {
                            wipe(aad);
                        }
                    });
            return secretId;
        } finally {
            wipe(payload);
            draft.close();
        }
    }

    @Override
    public void updateLogin(
            @NonNull SecretId secretId, @NonNull Consumer<LoginDraft> draftConsumer) {
        Objects.requireNonNull(secretId, "secretId");
        Objects.requireNonNull(draftConsumer, "draftConsumer");
        requireOpen();

        EncryptedSecretRecord existing =
                store.loadSecretRecord(vaultId, secretId)
                        .orElseThrow(() -> new ValidationException("Login secret does not exist"));
        if (existing.metadata().type() != SecretType.LOGIN_PASSWORD) {
            throw new ValidationException("Secret is not a login password");
        }

        LoginDraftImpl draft = new LoginDraftImpl();
        byte @Nullable [] payload = null;
        try {
            draftConsumer.accept(draft);
            draft.validate();

            Instant now = clock.instant();
            byte[] encodedPayload = LoginPayloadCodec.encode(draft);
            payload = encodedPayload;
            store.commitMutation(
                    vaultId,
                    revision -> {
                        SecretMetadata metadata =
                                new SecretMetadata(
                                        secretId,
                                        SecretType.LOGIN_PASSWORD,
                                        new SecretProfile(
                                                draft.title(),
                                                draft.classification(),
                                                draft.tags(),
                                                draft.attributes()),
                                        existing.metadata().createdAt(),
                                        now,
                                        revision);
                        byte[] aad = aad(metadata, revision);
                        try {
                            EncryptedEnvelope envelope =
                                    crypto.encrypt(vaultKey, encodedPayload, aad, now);
                            store.saveSecretRecord(
                                    new EncryptedSecretRecord(
                                            vaultId, metadata, envelope, revision));
                        } finally {
                            wipe(aad);
                        }
                    });
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
            byte[] encodedPayload = SecureNotePayloadCodec.encode(draft);
            payload = encodedPayload;
            store.commitMutation(
                    vaultId,
                    revision -> {
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
                                        revision);
                        byte[] aad = aad(metadata, revision);
                        try {
                            EncryptedEnvelope envelope =
                                    crypto.encrypt(vaultKey, encodedPayload, aad, now);
                            store.saveSecretRecord(
                                    new EncryptedSecretRecord(
                                            vaultId, metadata, envelope, revision));
                        } finally {
                            wipe(aad);
                        }
                    });
            return secretId;
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
    public @NonNull SecretId saveSecret(
            @NonNull SecretType type, @NonNull Consumer<StructuredSecretDraft> draftConsumer) {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(draftConsumer, "draftConsumer");
        requireOpen();
        requireStructuredType(type);

        StructuredSecretDraftImpl draft = new StructuredSecretDraftImpl();
        byte @Nullable [] payload = null;
        try {
            draftConsumer.accept(draft);
            draft.validate();

            SecretId secretId = new SecretId(UUID.randomUUID());
            Instant now = clock.instant();
            byte[] encodedPayload = StructuredSecretPayloadCodec.encode(draft);
            payload = encodedPayload;
            store.commitMutation(
                    vaultId,
                    revision -> {
                        SecretMetadata metadata =
                                new SecretMetadata(
                                        secretId,
                                        type,
                                        new SecretProfile(
                                                draft.title(),
                                                draft.classification(),
                                                draft.tags(),
                                                draft.attributes()),
                                        now,
                                        now,
                                        revision);
                        byte[] aad = aad(metadata, revision);
                        try {
                            EncryptedEnvelope envelope =
                                    crypto.encrypt(vaultKey, encodedPayload, aad, now);
                            store.saveSecretRecord(
                                    new EncryptedSecretRecord(
                                            vaultId, metadata, envelope, revision));
                        } finally {
                            wipe(aad);
                        }
                    });
            return secretId;
        } finally {
            wipe(payload);
            draft.close();
        }
    }

    @Override
    public void updateSecret(
            @NonNull SecretId secretId, @NonNull Consumer<StructuredSecretDraft> draftConsumer) {
        Objects.requireNonNull(secretId, "secretId");
        Objects.requireNonNull(draftConsumer, "draftConsumer");
        requireOpen();

        EncryptedSecretRecord existing =
                store.loadSecretRecord(vaultId, secretId)
                        .orElseThrow(
                                () -> new ValidationException("Structured secret does not exist"));
        SecretType type = existing.metadata().type();
        requireStructuredType(type);

        StructuredSecretDraftImpl draft = new StructuredSecretDraftImpl();
        byte @Nullable [] payload = null;
        try {
            draftConsumer.accept(draft);
            draft.validate();

            Instant now = clock.instant();
            byte[] encodedPayload = StructuredSecretPayloadCodec.encode(draft);
            payload = encodedPayload;
            store.commitMutation(
                    vaultId,
                    revision -> {
                        SecretMetadata metadata =
                                new SecretMetadata(
                                        secretId,
                                        type,
                                        new SecretProfile(
                                                draft.title(),
                                                draft.classification(),
                                                draft.tags(),
                                                draft.attributes()),
                                        existing.metadata().createdAt(),
                                        now,
                                        revision);
                        byte[] aad = aad(metadata, revision);
                        try {
                            EncryptedEnvelope envelope =
                                    crypto.encrypt(vaultKey, encodedPayload, aad, now);
                            store.saveSecretRecord(
                                    new EncryptedSecretRecord(
                                            vaultId, metadata, envelope, revision));
                        } finally {
                            wipe(aad);
                        }
                    });
        } finally {
            wipe(payload);
            draft.close();
        }
    }

    @Override
    public void withSecret(
            @NonNull SecretId secretId, @NonNull Consumer<StructuredSecretView> viewConsumer) {
        Objects.requireNonNull(secretId, "secretId");
        Objects.requireNonNull(viewConsumer, "viewConsumer");
        requireOpen();

        EncryptedSecretRecord record =
                store.loadSecretRecord(vaultId, secretId)
                        .orElseThrow(
                                () -> new ValidationException("Structured secret does not exist"));
        requireStructuredType(record.metadata().type());

        byte[] aad = aad(record.metadata(), record.revision());
        byte @Nullable [] payload = null;
        @Nullable StructuredSecretViewImpl view = null;
        try {
            payload = crypto.decrypt(vaultKey, record.payload(), aad);
            view = StructuredSecretPayloadCodec.decode(record.metadata(), payload);
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
        store.commitMutation(
                vaultId,
                revision -> {
                    @Nullable EncryptedSecretRecord existing =
                            store.loadSecretRecord(vaultId, secretId).orElse(null);
                    if (existing != null) {
                        store.saveDeletedSecretRecord(
                                new DeletedSecretRecord(
                                        vaultId,
                                        secretId,
                                        existing.metadata().type(),
                                        revision,
                                        clock.instant()));
                        store.deleteSecretRecord(vaultId, secretId);
                    }
                });
    }

    @Override
    public @NonNull List<SecretMetadata> listSecrets() {
        requireOpen();
        return store.listMetadata(vaultId);
    }

    @Override
    public @NonNull List<EncryptedSyncRecord> exportRecordsSince(long sinceRevision) {
        requireOpen();
        if (sinceRevision < 0) {
            throw new ValidationException("Since revision must not be negative");
        }
        return store.listSecretRecords(vaultId).stream()
                .filter(record -> record.revision() > sinceRevision)
                .map(this::exportRecord)
                .collect(
                        java.util.stream.Collectors.collectingAndThen(
                                java.util.stream.Collectors.toCollection(java.util.ArrayList::new),
                                records -> {
                                    store.listDeletedSecretRecords(vaultId).stream()
                                            .filter(record -> record.revision() > sinceRevision)
                                            .map(this::exportDeletedRecord)
                                            .forEach(records::add);
                                    records.sort(
                                            java.util.Comparator.comparing(
                                                            EncryptedSyncRecord::secretId)
                                                    .thenComparingLong(
                                                            EncryptedSyncRecord::revision));
                                    return List.copyOf(records);
                                }));
    }

    @Override
    public int importRecords(@NonNull List<EncryptedSyncRecord> records) {
        Objects.requireNonNull(records, "records");
        requireOpen();
        int imported = 0;
        for (EncryptedSyncRecord record : records) {
            imported += importRecord(record) ? 1 : 0;
        }
        return imported;
    }

    @Override
    public byte @NonNull [] wrapVaultKeyForDevice(
            byte @NonNull [] devicePublicKey, byte @NonNull [] context) {
        Objects.requireNonNull(devicePublicKey, "devicePublicKey");
        Objects.requireNonNull(context, "context");
        requireOpen();
        return crypto.wrapVaultKeyForDevice(vaultKey, devicePublicKey, context);
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
        if (metadata.classification().software() != null) {
            appendAad(value, metadata.classification().software());
        }
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

    private @NonNull EncryptedSyncRecord exportRecord(@NonNull EncryptedSecretRecord record) {
        SecretMetadata metadata = record.metadata();
        String vaultIdText = record.vaultId().value().toString();
        String secretIdText = metadata.id().value().toString();
        byte[] profileBytes = SyncRecordCodec.profileBytes(metadata);
        byte[] profileAad =
                SyncRecordCodec.profileAad(vaultIdText, secretIdText, record.revision());
        try {
            EncryptedEnvelope encryptedProfile =
                    crypto.encrypt(vaultKey, profileBytes, profileAad, clock.instant());
            return new EncryptedSyncRecord(
                    vaultIdText,
                    secretIdText,
                    record.revision(),
                    metadata.type().name(),
                    SyncRecordCodec.envelopeWithoutAad(encryptedProfile),
                    SyncRecordCodec.envelopeWithoutAad(record.payload()),
                    false);
        } finally {
            wipe(profileBytes);
            wipe(profileAad);
        }
    }

    private @NonNull EncryptedSyncRecord exportDeletedRecord(@NonNull DeletedSecretRecord record) {
        return new EncryptedSyncRecord(
                record.vaultId().value().toString(),
                record.secretId().value().toString(),
                record.revision(),
                record.secretType().name(),
                "",
                "",
                true);
    }

    private boolean importRecord(@NonNull EncryptedSyncRecord record) {
        Objects.requireNonNull(record, "record");
        if (!vaultId.value().toString().equals(record.vaultId())) {
            throw new ValidationException("Sync record belongs to a different vault");
        }
        SecretId secretId = new SecretId(UUID.fromString(record.secretId()));
        @Nullable EncryptedSecretRecord existing =
                store.loadSecretRecord(vaultId, secretId).orElse(null);
        @Nullable DeletedSecretRecord deleted =
                store.loadDeletedSecretRecord(vaultId, secretId).orElse(null);
        if (deleted != null && deleted.revision() >= record.revision()) {
            return false;
        }
        if (existing != null && existing.revision() >= record.revision()) {
            return false;
        }
        if (record.deleted()) {
            store.saveDeletedSecretRecord(
                    new DeletedSecretRecord(
                            vaultId,
                            secretId,
                            SecretType.valueOf(record.secretType()),
                            record.revision(),
                            clock.instant()));
            store.deleteSecretRecord(vaultId, secretId);
            return true;
        }

        byte[] profileAad =
                SyncRecordCodec.profileAad(record.vaultId(), record.secretId(), record.revision());
        byte @Nullable [] profileBytes = null;
        byte @Nullable [] payloadAad = null;
        try {
            EncryptedEnvelope profileEnvelope =
                    SyncRecordCodec.envelopeWithAad(record.encryptedProfile(), profileAad);
            profileBytes = crypto.decrypt(vaultKey, profileEnvelope, profileAad);
            SecretMetadata metadata = SyncRecordCodec.metadata(record, profileBytes);
            payloadAad = aad(metadata, record.revision());
            EncryptedEnvelope payloadEnvelope =
                    SyncRecordCodec.envelopeWithAad(record.envelope(), payloadAad);
            store.saveSecretRecord(
                    new EncryptedSecretRecord(
                            vaultId, metadata, payloadEnvelope, record.revision()));
            return true;
        } finally {
            wipe(profileAad);
            wipe(profileBytes);
            wipe(payloadAad);
        }
    }

    private void appendAad(@NonNull StringBuilder builder, @NonNull String value) {
        builder.append(value.length()).append(':').append(value).append('|');
    }

    private @NonNull String nullableAad(@Nullable String value) {
        return value == null ? "" : value;
    }

    private void requireStructuredType(@NonNull SecretType type) {
        if (type == SecretType.LOGIN_PASSWORD || type == SecretType.SECURE_NOTE) {
            throw new ValidationException("Secret type uses a dedicated payload format");
        }
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
