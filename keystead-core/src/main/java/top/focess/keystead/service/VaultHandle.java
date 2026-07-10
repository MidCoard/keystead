package top.focess.keystead.service;

import java.util.List;
import java.util.function.Consumer;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.KeyId;
import top.focess.keystead.model.SecretId;
import top.focess.keystead.model.SecretMetadata;
import top.focess.keystead.model.SecretType;
import top.focess.keystead.model.VaultId;

public interface VaultHandle extends AutoCloseable {

    @NonNull VaultId vaultId();

    @NonNull KeyId vaultKeyId();

    @NonNull SecretId saveLogin(@NonNull Consumer<LoginDraft> draftConsumer);

    void updateLogin(@NonNull SecretId secretId, @NonNull Consumer<LoginDraft> draftConsumer);

    void withLogin(@NonNull SecretId secretId, @NonNull Consumer<LoginSecretView> viewConsumer);

    @NonNull SecretId saveSecureNote(@NonNull Consumer<SecureNoteDraft> draftConsumer);

    void withSecureNote(@NonNull SecretId secretId, @NonNull Consumer<SecureNoteView> viewConsumer);

    @NonNull SecretId saveSecret(
            @NonNull SecretType type, @NonNull Consumer<StructuredSecretDraft> draftConsumer);

    void updateSecret(
            @NonNull SecretId secretId, @NonNull Consumer<StructuredSecretDraft> draftConsumer);

    void withSecret(
            @NonNull SecretId secretId, @NonNull Consumer<StructuredSecretView> viewConsumer);

    void deleteSecret(@NonNull SecretId secretId);

    @NonNull List<SecretMetadata> listSecrets();

    @NonNull List<EncryptedSyncRecord> exportRecordsSince(long sinceRevision);

    int importRecords(@NonNull List<EncryptedSyncRecord> records);

    @NonNull SyncImportReport importRecordsWithReport(@NonNull List<EncryptedSyncRecord> records);

    byte @NonNull [] wrapVaultKeyForDevice(
            byte @NonNull [] devicePublicKey, byte @NonNull [] context);

    @NonNull DeviceVaultKeyPackage wrapVaultKeyPackageForDevice(
            byte @NonNull [] devicePublicKey, byte @NonNull [] context);

    boolean isClosed();

    @Override
    void close();
}
