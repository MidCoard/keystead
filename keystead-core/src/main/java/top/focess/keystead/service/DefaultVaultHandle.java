package top.focess.keystead.service;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.crypto.CryptoException;
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
            SecretTypeSchemaValidator.validate(
                    SecretTypeSchema.forType(type), draft.fields().keySet());

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
            SecretTypeSchemaValidator.validate(
                    SecretTypeSchema.forType(type), draft.fields().keySet());

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
                                            java.util.Comparator.comparingLong(
                                                            EncryptedSyncRecord::revision)
                                                    .thenComparing(EncryptedSyncRecord::secretId));
                                    return List.copyOf(records);
                                }));
    }

    @Override
    public int importRecords(@NonNull List<EncryptedSyncRecord> records) {
        return importRecordsWithReport(records).imported();
    }

    @Override
    public @NonNull SyncImportReport importRecordsWithReport(
            @NonNull List<EncryptedSyncRecord> records) {
        Objects.requireNonNull(records, "records");
        requireOpen();
        requireSyncImportBatchPreflight(records);
        int imported = 0;
        int skipped = 0;
        List<SyncImportConflict> conflicts = new ArrayList<>();
        for (EncryptedSyncRecord record : records) {
            ImportOutcome outcome = importRecord(record);
            if (outcome.imported()) {
                imported++;
            } else if (outcome.conflict() != null) {
                conflicts.add(outcome.conflict());
            } else {
                skipped++;
            }
        }
        return new SyncImportReport(imported, skipped, conflicts);
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
        return SecretRecordAad.encode(vaultId, metadata, revision);
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

    private @NonNull ImportOutcome importRecord(@NonNull EncryptedSyncRecord record) {
        Objects.requireNonNull(record, "record");
        requireSyncRecordPreflight(record);
        SecretId secretId = new SecretId(UUID.fromString(record.secretId()));
        @Nullable EncryptedSecretRecord existing =
                store.loadSecretRecord(vaultId, secretId).orElse(null);
        @Nullable DeletedSecretRecord deleted =
                store.loadDeletedSecretRecord(vaultId, secretId).orElse(null);
        if (deleted != null && deleted.revision() >= record.revision()) {
            return skippedOrConflict(record, deleted.revision(), true);
        }
        if (existing != null && existing.revision() >= record.revision()) {
            return skippedOrConflict(record, existing.revision(), false);
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
            return ImportOutcome.importedOutcome();
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
            return ImportOutcome.importedOutcome();
        } finally {
            wipe(profileAad);
            wipe(profileBytes);
            wipe(payloadAad);
        }
    }

    private void requireSyncImportBatchPreflight(@NonNull List<EncryptedSyncRecord> records) {
        Set<String> secretIds = new HashSet<>();
        for (EncryptedSyncRecord record : records) {
            requireSyncRecordPreflight(record);
            if (!secretIds.add(record.secretId())) {
                throw new ValidationException("Sync import batch contains duplicate secret id");
            }
        }
    }

    private void requireSyncRecordPreflight(@NonNull EncryptedSyncRecord record) {
        Objects.requireNonNull(record, "record");
        requireSyncRecordVault(record);
        try {
            UUID.fromString(record.secretId());
        } catch (IllegalArgumentException e) {
            throw new ValidationException("Sync record secret id is invalid", e);
        }
        try {
            SecretType.valueOf(record.secretType());
        } catch (IllegalArgumentException e) {
            throw new ValidationException("Sync record secret type is unsupported", e);
        }
        if (!record.deleted()) {
            requireActiveSyncRecordDecodable(record);
        }
    }

    private void requireActiveSyncRecordDecodable(@NonNull EncryptedSyncRecord record) {
        byte[] profileAad =
                SyncRecordCodec.profileAad(record.vaultId(), record.secretId(), record.revision());
        byte @Nullable [] profileBytes = null;
        byte @Nullable [] payloadAad = null;
        byte @Nullable [] payloadBytes = null;
        try {
            EncryptedEnvelope profileEnvelope =
                    SyncRecordCodec.envelopeWithAad(record.encryptedProfile(), profileAad);
            profileBytes = crypto.decrypt(vaultKey, profileEnvelope, profileAad);
            SecretMetadata metadata = SyncRecordCodec.metadata(record, profileBytes);
            payloadAad = aad(metadata, record.revision());
            EncryptedEnvelope payloadEnvelope =
                    SyncRecordCodec.envelopeWithAad(record.envelope(), payloadAad);
            payloadBytes = crypto.decrypt(vaultKey, payloadEnvelope, payloadAad);
        } catch (CryptoException | IllegalArgumentException e) {
            throw new ValidationException("Active sync record cannot be decoded", e);
        } finally {
            wipe(profileAad);
            wipe(profileBytes);
            wipe(payloadAad);
            wipe(payloadBytes);
        }
    }

    private void requireSyncRecordVault(@NonNull EncryptedSyncRecord record) {
        if (!vaultId.value().toString().equals(record.vaultId())) {
            throw new ValidationException("Sync record belongs to a different vault");
        }
    }

    private @NonNull ImportOutcome skippedOrConflict(
            @NonNull EncryptedSyncRecord record, long localRevision, boolean localDeleted) {
        if (localDeleted != record.deleted()) {
            return ImportOutcome.conflict(
                    new SyncImportConflict(
                            record.vaultId(),
                            record.secretId(),
                            localRevision,
                            record.revision(),
                            localDeleted,
                            record.deleted()));
        }
        return ImportOutcome.skippedOutcome();
    }

    private record ImportOutcome(boolean imported, @Nullable SyncImportConflict conflict) {

        private static @NonNull ImportOutcome importedOutcome() {
            return new ImportOutcome(true, null);
        }

        private static @NonNull ImportOutcome skippedOutcome() {
            return new ImportOutcome(false, null);
        }

        private static @NonNull ImportOutcome conflict(@NonNull SyncImportConflict conflict) {
            return new ImportOutcome(false, Objects.requireNonNull(conflict, "conflict"));
        }
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
