package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import top.focess.keystead.crypto.DefaultCryptoService;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.memory.SecretMemoryProvider;
import top.focess.keystead.memory.Wipe;
import top.focess.keystead.model.*;
import top.focess.keystead.store.OneFileVaultStore;

class CanonicalSyncContentKeyTest {
    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-09-05T01:02:03.123456789Z"), ZoneOffset.UTC);
    private static final char[] PASSWORD = "canonical-sync-fixture".toCharArray();
    @TempDir Path temp;

    @Test
    void authenticatesLegacyCrLfAndOldOrderingWithoutCreatingAConflictOrChangingRevision()
            throws Exception {
        var crypto = new DefaultCryptoService();
        var service = new DefaultVaultService(crypto, CLOCK);
        Path source = temp.resolve("source"), empty = temp.resolve("empty");
        try (var vault = service.createVault(source, PASSWORD)) {}
        Files.copy(source, empty);
        EncryptedSyncRecord canonical;
        try (var vault = service.openVault(source, PASSWORD);
                var value =
                        SecretBuffer.fromChars(
                                "fixture-secret".toCharArray(), SecretMemoryProvider.heap())) {
            vault.saveSecret(
                    SecretType.GENERIC_SECRET,
                    d ->
                            d.title("Title:=\\\n测试")
                                    .tag("tag:=\\")
                                    .tag("second")
                                    .attribute("custom:key\\", "value\nwith\r\nlines=测试")
                                    .classification(
                                            new SecretClassification(
                                                    "category",
                                                    null,
                                                    "software\\",
                                                    "account=one",
                                                    Set.of("label")))
                                    .field("value", value));
            canonical = vault.exportRecordsSince(0).getFirst();
        }
        List<EncryptedSyncRecord> legacy = new ArrayList<>();
        try (var store = OneFileVaultStore.open(crypto, source, PASSWORD, CLOCK)) {
            legacy.add(legacyRecord(store, false, true, false));
            legacy.add(legacyRecord(store, true, false, false));
            legacy.add(legacyRecord(store, true, true, false));
        }
        for (int index = 0; index < legacy.size(); index++) {
            var row = legacy.get(index);
            assertNotEquals(canonical.contentKey(), row.contentKey());
            assertNotEquals(SyncRecordEventId.of(canonical), SyncRecordEventId.of(row));
            Path target = temp.resolve("target-" + index);
            Files.copy(empty, target);
            try (var vault = service.openVault(target, PASSWORD)) {
                assertEquals(canonical.contentKey(), vault.canonicalSyncContentKey(row));
                assertEquals(1, vault.importRecords(List.of(row)));
                var reexport = vault.exportRecordsSince(0).getFirst();
                assertEquals(row.revision(), reexport.revision());
                assertEquals(canonical.contentKey(), reexport.contentKey());
                assertEquals(
                        vault.canonicalSyncContentKey(row),
                        vault.canonicalSyncContentKey(reexport));
                assertEquals("Title:=\\\n测试", vault.listSecrets().getFirst().title());
            }
        }
    }

    @Test
    void rejectsForgedLegacyKeyCiphertextAndAuthenticatedInvalidTypedPayload() throws Exception {
        var crypto = new DefaultCryptoService();
        var service = new DefaultVaultService(crypto, CLOCK);
        Path source = temp.resolve("source");
        EncryptedSyncRecord canonical;
        try (var vault = service.createVault(source, PASSWORD);
                var value =
                        SecretBuffer.fromChars(
                                "fixture".toCharArray(), SecretMemoryProvider.heap())) {
            vault.saveSecret(SecretType.GENERIC_SECRET, d -> d.title("Note").field("value", value));
            canonical = vault.exportRecordsSince(0).getFirst();
        }
        EncryptedSyncRecord legacy, invalidTyped;
        try (var store = OneFileVaultStore.open(crypto, source, PASSWORD, CLOCK)) {
            legacy = legacyRecord(store, true, true, false);
            invalidTyped = legacyRecord(store, true, true, true);
        }
        try (var vault = service.openVault(source, PASSWORD)) {
            var forgedKey =
                    new EncryptedSyncRecord(
                            legacy.fingerprint(),
                            legacy.secretId(),
                            legacy.revision(),
                            legacy.secretType(),
                            legacy.encryptedProfile(),
                            legacy.envelope(),
                            false,
                            canonical.contentKey());
            assertThrows(ValidationException.class, () -> vault.canonicalSyncContentKey(forgedKey));
            var corrupt =
                    new EncryptedSyncRecord(
                            legacy.fingerprint(),
                            legacy.secretId(),
                            legacy.revision(),
                            legacy.secretType(),
                            legacy.encryptedProfile(),
                            "corrupt",
                            false,
                            legacy.contentKey());
            assertThrows(ValidationException.class, () -> vault.canonicalSyncContentKey(corrupt));
            assertThrows(
                    ValidationException.class, () -> vault.canonicalSyncContentKey(invalidTyped));
            assertEquals(canonical.revision(), vault.listSecrets().getFirst().revision());
        }
    }

    private EncryptedSyncRecord legacyRecord(
            OneFileVaultStore store, boolean crlf, boolean reverse, boolean invalidTyped) {
        var stored = store.listSecretRecords().getFirst();
        var metadata = stored.metadata();
        String fingerprint = store.vaultFingerprint().toHexString();
        String secretId = metadata.secretId().value().toString();
        var lines =
                new ArrayList<>(
                        new String(SyncRecordCodec.profileBytes(metadata), StandardCharsets.UTF_8)
                                .lines()
                                .toList());
        if (reverse) Collections.reverse(lines);
        String separator = crlf ? "\r\n" : "\n";
        byte[] profile =
                (String.join(separator, lines) + separator).getBytes(StandardCharsets.UTF_8);
        byte[] profileAad = SyncRecordCodec.profileAad(fingerprint, secretId, stored.revision());
        byte[] payloadAad =
                SecretRecordAad.encode(store.vaultFingerprint(), metadata, stored.revision());
        byte[] payload = store.crypto().decrypt(store.vaultKey(), stored.payload(), payloadAad);
        try {
            var envelope = stored.payload();
            if (invalidTyped) {
                payload[3] = 99; // authenticated, but not a supported structured payload version
                envelope =
                        store.crypto()
                                .encrypt(store.vaultKey(), payload, payloadAad, CLOCK.instant());
            }
            var encryptedProfile =
                    store.crypto().encrypt(store.vaultKey(), profile, profileAad, CLOCK.instant());
            return new EncryptedSyncRecord(
                    fingerprint,
                    secretId,
                    stored.revision(),
                    metadata.secretType().name(),
                    SyncRecordCodec.envelopeWithoutAad(encryptedProfile),
                    SyncRecordCodec.envelopeWithoutAad(envelope),
                    false,
                    store.crypto().syncContentKey(store.vaultKey(), profile, payload));
        } finally {
            Wipe.wipe(profile);
            Wipe.wipe(payload);
            Wipe.wipe(profileAad);
            Wipe.wipe(payloadAad);
        }
    }
}
