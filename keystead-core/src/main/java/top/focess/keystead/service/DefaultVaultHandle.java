package top.focess.keystead.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
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
import top.focess.keystead.memory.Wipe;
import top.focess.keystead.model.*;
import top.focess.keystead.store.VaultKeyRotation;
import top.focess.keystead.store.VaultStore;

final class DefaultVaultHandle implements VaultHandle {

    private final VaultId vaultId;
    private final VaultKey vaultKey;
    private final VaultStore store;
    private final DefaultCryptoService crypto;
    private final Clock clock;
    private boolean closed;
    private boolean rotationPrepared;

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
    public synchronized @NonNull KeyId vaultKeyId() {
        requireOpen();
        return vaultKey.keyId();
    }

    @Override
    public synchronized @NonNull SecretId saveLogin(@NonNull Consumer<LoginDraft> draftConsumer) {
        Objects.requireNonNull(draftConsumer, "draftConsumer");
        requireOpen();
        requireMutable();

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
                            Wipe.wipe(aad);
                        }
                    });
            return secretId;
        } finally {
            Wipe.wipe(payload);
            draft.close();
        }
    }

    @Override
    public synchronized void updateLogin(
            @NonNull SecretId secretId, @NonNull Consumer<LoginDraft> draftConsumer) {
        Objects.requireNonNull(secretId, "secretId");
        Objects.requireNonNull(draftConsumer, "draftConsumer");
        requireOpen();
        requireMutable();

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
                            Wipe.wipe(aad);
                        }
                    });
        } finally {
            Wipe.wipe(payload);
            draft.close();
        }
    }

    @Override
    public synchronized void withLogin(
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
            Wipe.wipe(payload);
            Wipe.wipe(aad);
        }
    }

    @Override
    public synchronized @NonNull SecretId saveSecureNote(
            @NonNull Consumer<SecureNoteDraft> draftConsumer) {
        Objects.requireNonNull(draftConsumer, "draftConsumer");
        requireOpen();
        requireMutable();

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
                            Wipe.wipe(aad);
                        }
                    });
            return secretId;
        } finally {
            Wipe.wipe(payload);
            draft.close();
        }
    }

    @Override
    public synchronized void withSecureNote(
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
            Wipe.wipe(payload);
            Wipe.wipe(aad);
        }
    }

    @Override
    public synchronized @NonNull SecretId saveSecret(
            @NonNull SecretType type, @NonNull Consumer<StructuredSecretDraft> draftConsumer) {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(draftConsumer, "draftConsumer");
        requireOpen();
        requireMutable();
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
                            Wipe.wipe(aad);
                        }
                    });
            return secretId;
        } finally {
            Wipe.wipe(payload);
            draft.close();
        }
    }

    @Override
    public synchronized void updateSecret(
            @NonNull SecretId secretId, @NonNull Consumer<StructuredSecretDraft> draftConsumer) {
        Objects.requireNonNull(secretId, "secretId");
        Objects.requireNonNull(draftConsumer, "draftConsumer");
        requireOpen();
        requireMutable();

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
                            Wipe.wipe(aad);
                        }
                    });
        } finally {
            Wipe.wipe(payload);
            draft.close();
        }
    }

    @Override
    public synchronized void withSecret(
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
            Wipe.wipe(payload);
            Wipe.wipe(aad);
        }
    }

    @Override
    public synchronized void deleteSecret(@NonNull SecretId secretId) {
        Objects.requireNonNull(secretId, "secretId");
        requireOpen();
        requireMutable();
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
    public synchronized @NonNull List<SecretMetadata> listSecrets() {
        requireOpen();
        return store.listMetadata(vaultId);
    }

    @Override
    public synchronized @NonNull List<EncryptedSyncRecord> exportRecordsSince(long sinceRevision) {
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
    public synchronized int importRecords(@NonNull List<EncryptedSyncRecord> records) {
        return importRecordsWithReport(records).imported();
    }

    @Override
    public synchronized @NonNull SyncImportReport importRecordsWithReport(
            @NonNull List<EncryptedSyncRecord> records) {
        Objects.requireNonNull(records, "records");
        requireOpen();
        requireMutable();
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
    public synchronized byte @NonNull [] wrapVaultKeyForDevice(
            byte @NonNull [] devicePublicKey, byte @NonNull [] context) {
        Objects.requireNonNull(devicePublicKey, "devicePublicKey");
        Objects.requireNonNull(context, "context");
        requireOpen();
        return crypto.wrapVaultKeyForDevice(vaultKey, devicePublicKey, context);
    }

    @Override
    public synchronized @NonNull DeviceVaultKeyPackage wrapVaultKeyPackageForDevice(
            byte @NonNull [] devicePublicKey, byte @NonNull [] context) {
        Objects.requireNonNull(devicePublicKey, "devicePublicKey");
        Objects.requireNonNull(context, "context");
        requireOpen();
        return new DeviceVaultKeyPackage(
                vaultKey.keyId(),
                DefaultVaultService.DEVICE_KEY_PACKAGE_ALGORITHM,
                crypto.wrapVaultKeyForDevice(vaultKey, devicePublicKey, context));
    }

    @Override
    public synchronized @NonNull PreparedVaultKeyRotation prepareVaultKeyRotation() {
        requireOpen();
        KeyId targetKeyId = new KeyId("vault-key-" + vaultId.value() + "-" + UUID.randomUUID());
        VaultKey targetKey = crypto.generateVaultKey(targetKeyId);
        return beginPreparedRotation(targetKey, null);
    }

    @Override
    public synchronized @NonNull PreparedVaultKeyRotation resumeVaultKeyRotation(
            @NonNull DeviceVaultKeyPackage stagedPackage,
            byte @NonNull [] devicePrivateKey,
            byte @NonNull [] context) {
        Objects.requireNonNull(stagedPackage, "stagedPackage");
        Objects.requireNonNull(devicePrivateKey, "devicePrivateKey");
        Objects.requireNonNull(context, "context");
        requireOpen();
        if (vaultKey.keyId().equals(stagedPackage.vaultKeyId())) {
            throw new ValidationException("Staged package must contain a new vault key");
        }
        if (!DefaultVaultService.DEVICE_KEY_PACKAGE_ALGORITHM.equals(
                stagedPackage.keyAlgorithm())) {
            throw new ValidationException("Staged package algorithm is unsupported");
        }
        byte[] encryptedVaultKey = stagedPackage.encryptedVaultKey();
        VaultKey targetKey;
        try {
            targetKey =
                    crypto.unwrapVaultKeyFromDevicePackage(
                            stagedPackage.vaultKeyId(),
                            encryptedVaultKey,
                            devicePrivateKey,
                            context);
        } finally {
            Wipe.wipe(encryptedVaultKey);
        }
        return beginPreparedRotation(targetKey, stagedPackage);
    }

    @Override
    public synchronized boolean isClosed() {
        return closed;
    }

    @Override
    public synchronized void close() {
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
            Wipe.wipe(profileBytes);
            Wipe.wipe(profileAad);
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
            Wipe.wipe(profileAad);
            Wipe.wipe(profileBytes);
            Wipe.wipe(payloadAad);
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
            Wipe.wipe(profileAad);
            Wipe.wipe(profileBytes);
            Wipe.wipe(payloadAad);
            Wipe.wipe(payloadBytes);
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

    private void requireMutable() {
        if (rotationPrepared) {
            throw new IllegalStateException("Vault key rotation is prepared");
        }
    }

    private synchronized @NonNull PreparedVaultKeyRotation beginPreparedRotation(
            @NonNull VaultKey targetKey, @Nullable DeviceVaultKeyPackage stagedPackage) {
        requireOpen();
        if (rotationPrepared) {
            targetKey.close();
            throw new IllegalStateException("Vault key rotation is already prepared");
        }
        rotationPrepared = true;
        try {
            return new DefaultPreparedVaultKeyRotation(targetKey, stagedPackage);
        } catch (RuntimeException | Error e) {
            rotationPrepared = false;
            targetKey.close();
            throw e;
        }
    }

    private synchronized void releasePreparedRotation() {
        rotationPrepared = false;
    }

    private synchronized void completePreparedRotation() {
        requireOpen();
        vaultKey.close();
        closed = true;
        rotationPrepared = false;
    }

    private final class DefaultPreparedVaultKeyRotation implements PreparedVaultKeyRotation {

        private final KeyId sourceKeyId = vaultKey.keyId();
        private final VaultKey targetKey;
        private final VaultHeader previousHeader;
        private final List<EncryptedSecretRecord> rotatedRecords;
        private final Set<String> acceptedPackageFingerprints = new HashSet<>();
        private boolean committed;
        private boolean closed;
        private boolean targetTransferred;

        private DefaultPreparedVaultKeyRotation(
                @NonNull VaultKey targetKey, @Nullable DeviceVaultKeyPackage stagedPackage) {
            this.targetKey = targetKey;
            this.previousHeader =
                    store.loadVaultHeader(vaultId)
                            .orElseThrow(() -> new ValidationException("Vault does not exist"));
            if (!previousHeader.vaultKeyId().equals(sourceKeyId)) {
                throw new ValidationException("Vault key changed before rotation preparation");
            }
            this.rotatedRecords = rotateRecords(targetKey);
            if (stagedPackage != null) {
                acceptedPackageFingerprints.add(packageFingerprint(stagedPackage));
            }
        }

        @Override
        public @NonNull VaultId vaultId() {
            return vaultId;
        }

        @Override
        public @NonNull KeyId sourceVaultKeyId() {
            return sourceKeyId;
        }

        @Override
        public synchronized @NonNull KeyId targetVaultKeyId() {
            return targetKey.keyId();
        }

        @Override
        public synchronized @NonNull DeviceVaultKeyPackage wrapVaultKeyPackageForDevice(
                byte @NonNull [] publicKey, byte @NonNull [] context) {
            Objects.requireNonNull(publicKey, "publicKey");
            Objects.requireNonNull(context, "context");
            synchronized (DefaultVaultHandle.this) {
                requirePreparedOpen();
                DeviceVaultKeyPackage keyPackage =
                        new DeviceVaultKeyPackage(
                                targetKey.keyId(),
                                DefaultVaultService.DEVICE_KEY_PACKAGE_ALGORITHM,
                                crypto.wrapVaultKeyForDevice(targetKey, publicKey, context));
                acceptedPackageFingerprints.add(packageFingerprint(keyPackage));
                return keyPackage;
            }
        }

        @Override
        public synchronized @NonNull VaultHandle commitWithDevicePackage(
                @NonNull DeviceVaultKeyPackage localPackage) {
            Objects.requireNonNull(localPackage, "localPackage");
            synchronized (DefaultVaultHandle.this) {
                requirePreparedOpen();
                if (!targetKey.keyId().equals(localPackage.vaultKeyId())
                        || !DefaultVaultService.DEVICE_KEY_PACKAGE_ALGORITHM.equals(
                                localPackage.keyAlgorithm())
                        || !acceptedPackageFingerprints.contains(
                                packageFingerprint(localPackage))) {
                    throw new ValidationException(
                            "Local device package was not produced by this rotation");
                }

                byte[] wrapped = localPackage.encryptedVaultKey();
                try {
                    Instant now = clock.instant();
                    store.commitVaultKeyRotation(
                            new VaultKeyRotation(
                                    new VaultHeader(
                                            vaultId,
                                            previousHeader.formatVersion(),
                                            localPackage.keyAlgorithm(),
                                            new byte[0],
                                            1,
                                            targetKey.keyId(),
                                            wrapped,
                                            previousHeader.createdAt(),
                                            now),
                                    rotatedRecords));
                    completePreparedRotation();
                    DefaultVaultHandle rotated =
                            new DefaultVaultHandle(vaultId, targetKey, store, crypto, clock);
                    committed = true;
                    targetTransferred = true;
                    return rotated;
                } finally {
                    Wipe.wipe(wrapped);
                }
            }
        }

        @Override
        public synchronized boolean isCommitted() {
            return committed;
        }

        @Override
        public synchronized void close() {
            if (!closed) {
                if (!targetTransferred) {
                    targetKey.close();
                }
                rotatedRecords.clear();
                acceptedPackageFingerprints.clear();
                if (!committed) {
                    releasePreparedRotation();
                }
                closed = true;
            }
        }

        @Override
        public synchronized @NonNull String toString() {
            return "PreparedVaultKeyRotation[vaultId=%s, sourceVaultKeyId=%s, targetVaultKeyId=%s, packages=%d, committed=%s, closed=%s]"
                    .formatted(
                            vaultId,
                            sourceKeyId,
                            targetKey.keyId(),
                            acceptedPackageFingerprints.size(),
                            committed,
                            closed);
        }

        private @NonNull List<EncryptedSecretRecord> rotateRecords(@NonNull VaultKey nextKey) {
            List<EncryptedSecretRecord> records = new ArrayList<>();
            for (EncryptedSecretRecord record : store.listSecretRecords(vaultId)) {
                byte[] aad = SecretRecordAad.encode(vaultId, record.metadata(), record.revision());
                byte @Nullable [] plaintext = null;
                try {
                    plaintext = crypto.decrypt(vaultKey, record.payload(), aad);
                    records.add(
                            new EncryptedSecretRecord(
                                    vaultId,
                                    record.metadata(),
                                    crypto.encrypt(nextKey, plaintext, aad, clock.instant()),
                                    record.revision()));
                } finally {
                    Wipe.wipe(aad);
                    Wipe.wipe(plaintext);
                }
            }
            return records;
        }

        private void requirePreparedOpen() {
            if (closed) {
                throw new IllegalStateException("Prepared vault key rotation is closed");
            }
            if (committed) {
                throw new IllegalStateException("Prepared vault key rotation is committed");
            }
            requireOpen();
        }
    }

    private @NonNull String packageFingerprint(@NonNull DeviceVaultKeyPackage keyPackage) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            updateDigest(digest, keyPackage.vaultKeyId().value().getBytes(StandardCharsets.UTF_8));
            updateDigest(digest, keyPackage.keyAlgorithm().getBytes(StandardCharsets.UTF_8));
            byte[] encryptedVaultKey = keyPackage.encryptedVaultKey();
            try {
                updateDigest(digest, encryptedVaultKey);
                return Base64.getUrlEncoder().withoutPadding().encodeToString(digest.digest());
            } finally {
                Wipe.wipe(encryptedVaultKey);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    private void updateDigest(@NonNull MessageDigest digest, byte @NonNull [] value) {
        digest.update((byte) (value.length >>> 24));
        digest.update((byte) (value.length >>> 16));
        digest.update((byte) (value.length >>> 8));
        digest.update((byte) value.length);
        digest.update(value);
    }
}
