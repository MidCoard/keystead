package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import top.focess.keystead.model.*;
import top.focess.keystead.store.FileVaultStore;

class VaultBackupServiceTest {

    private static final Clock CLOCK =
            Clock.fixed(Instant.parse("2026-07-03T00:00:00Z"), ZoneOffset.UTC);
    private static final VaultId VAULT_ID = new VaultId(new UUID(0L, 1L));

    private final VaultBackupService backup = new VaultBackupService(CLOCK);

    @TempDir Path tempDir;

    @Test
    void exportAndRestoreRoundTripsIntoFreshStore() {
        FileVaultStore source = new FileVaultStore(tempDir.resolve("source"));
        source.saveVaultHeader(header());
        source.saveSecretRecord(record(secretId(2L), "alpha", 1L));
        source.saveSecretRecord(record(secretId(3L), "beta", 2L));
        source.saveDeletedSecretRecord(deleted(secretId(4L), 3L));

        BackupArchive archive = backup.export(source, VAULT_ID);
        assertEquals(2, archive.records().size());
        assertEquals(1, archive.tombstones().size());
        assertEquals(VAULT_ID, archive.manifest().vaultId());
        assertEquals(2, archive.manifest().recordCount());

        FileVaultStore target = new FileVaultStore(tempDir.resolve("target"));
        BackupImportReport report = backup.restore(target, archive);

        assertEquals(2, report.imported());
        assertEquals(0, report.skipped());
        assertEquals(1, report.tombstones());
        assertTrue(report.conflicts().isEmpty());
        assertEquals(Optional.of(header()), target.loadVaultHeader(VAULT_ID));
        assertEquals(2, target.listSecretRecords(VAULT_ID).size());
        assertEquals(1, target.listDeletedSecretRecords(VAULT_ID).size());
    }

    @Test
    void restoreSkipsConflictingRecordsWithoutDestroyingExistingData() {
        FileVaultStore source = new FileVaultStore(tempDir.resolve("source"));
        source.saveVaultHeader(header());
        source.saveSecretRecord(record(secretId(2L), "older", 1L));

        BackupArchive archive = backup.export(source, VAULT_ID);

        FileVaultStore target = new FileVaultStore(tempDir.resolve("target"));
        target.saveVaultHeader(header());
        target.saveSecretRecord(record(secretId(2L), "newer", 5L));

        BackupImportReport report = backup.restore(target, archive);

        assertEquals(0, report.imported());
        assertEquals(1, report.skipped());
        assertEquals(1, report.conflicts().size());
        BackupConflict conflict = report.conflicts().get(0);
        assertEquals(secretId(2L), conflict.secretId());
        assertEquals(5L, conflict.existingRevision());
        assertEquals(1L, conflict.incomingRevision());

        List<EncryptedSecretRecord> restored = target.listSecretRecords(VAULT_ID);
        assertEquals(1, restored.size());
        assertEquals(5L, restored.get(0).revision());
        assertEquals("newer", restored.get(0).metadata().title());
    }

    @Test
    void restoreSkipsRecordOlderThanExistingTombstone() {
        FileVaultStore source = new FileVaultStore(tempDir.resolve("source"));
        source.saveVaultHeader(header());
        source.saveSecretRecord(record(secretId(2L), "older", 1L));

        BackupArchive archive = backup.export(source, VAULT_ID);

        FileVaultStore target = new FileVaultStore(tempDir.resolve("target"));
        target.saveVaultHeader(header());
        target.saveDeletedSecretRecord(deleted(secretId(2L), 5L));

        BackupImportReport report = backup.restore(target, archive);

        assertEquals(0, report.imported());
        assertEquals(1, report.skipped());
        assertEquals(1, report.conflicts().size());
        BackupConflict conflict = report.conflicts().get(0);
        assertEquals(secretId(2L), conflict.secretId());
        assertEquals(5L, conflict.existingRevision());
        assertEquals(1L, conflict.incomingRevision());
        assertEquals(List.of(), target.listSecretRecords(VAULT_ID));
        assertEquals(1, target.listDeletedSecretRecords(VAULT_ID).size());
        assertEquals(5L, target.listDeletedSecretRecords(VAULT_ID).getFirst().revision());
    }

    @Test
    void restoreSkipsTombstoneOlderThanExistingRecord() {
        FileVaultStore source = new FileVaultStore(tempDir.resolve("source"));
        source.saveVaultHeader(header());
        source.saveDeletedSecretRecord(deleted(secretId(2L), 1L));

        BackupArchive archive = backup.export(source, VAULT_ID);

        FileVaultStore target = new FileVaultStore(tempDir.resolve("target"));
        target.saveVaultHeader(header());
        target.saveSecretRecord(record(secretId(2L), "newer", 5L));

        BackupImportReport report = backup.restore(target, archive);

        assertEquals(0, report.imported());
        assertEquals(1, report.skipped());
        assertEquals(0, report.tombstones());
        assertEquals(1, report.conflicts().size());
        BackupConflict conflict = report.conflicts().get(0);
        assertEquals(secretId(2L), conflict.secretId());
        assertEquals(5L, conflict.existingRevision());
        assertEquals(1L, conflict.incomingRevision());
        assertEquals(1, target.listSecretRecords(VAULT_ID).size());
        assertEquals(5L, target.listSecretRecords(VAULT_ID).getFirst().revision());
        assertEquals(List.of(), target.listDeletedSecretRecords(VAULT_ID));
    }

    @Test
    void archiveSurvivesSerializationRoundTrip() throws Exception {
        FileVaultStore source = new FileVaultStore(tempDir.resolve("source"));
        source.saveVaultHeader(header());
        source.saveSecretRecord(record(secretId(2L), "alpha", 1L));
        source.saveDeletedSecretRecord(deleted(secretId(3L), 2L));

        BackupArchive archive = backup.export(source, VAULT_ID);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        backup.writeTo(archive, out);

        BackupReadResult read = backup.readFrom(new ByteArrayInputStream(out.toByteArray()));
        assertEquals(0, read.unsupported());
        BackupArchive restored = read.archive();
        assertEquals(archive.manifest(), restored.manifest());
        assertEquals(archive.vaultHeader(), restored.vaultHeader());
        assertEquals(archive.records(), restored.records());
        assertEquals(archive.tombstones(), restored.tombstones());

        FileVaultStore target = new FileVaultStore(tempDir.resolve("target"));
        BackupImportReport report = backup.restore(target, restored);
        assertEquals(1, report.imported());
        assertEquals(1, report.tombstones());
    }

    @Test
    void serializedRecordEntriesDoNotStoreEnvelopeAad() throws Exception {
        FileVaultStore source = new FileVaultStore(tempDir.resolve("source"));
        source.saveVaultHeader(header());
        source.saveSecretRecord(record(secretId(2L), "alpha", 1L));

        BackupArchive archive = backup.export(source, VAULT_ID);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        backup.writeTo(archive, out);

        String recordEntry =
                zipEntryText(
                        out.toByteArray(),
                        "records/00000000-0000-0000-0000-000000000002.properties");

        assertFalse(recordEntry.contains("envelope.aad"));
    }

    @Test
    void readFromRejectsTamperedRecordEntryDigest() throws Exception {
        FileVaultStore source = new FileVaultStore(tempDir.resolve("source"));
        source.saveVaultHeader(header());
        source.saveSecretRecord(record(secretId(2L), "alpha", 1L));

        BackupArchive archive = backup.export(source, VAULT_ID);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        backup.writeTo(archive, out);

        String entryName = "records/00000000-0000-0000-0000-000000000002.properties";
        String originalEntry = zipEntryText(out.toByteArray(), entryName);
        byte[] tampered =
                replaceZipEntryText(out.toByteArray(), entryName, originalEntry + "\n#tampered\n");

        assertThrows(
                ValidationException.class,
                () -> backup.readFrom(new ByteArrayInputStream(tampered)));
    }

    @Test
    void readFromRejectsTamperedRecordEntryWhenManifestIsLast() throws Exception {
        FileVaultStore source = new FileVaultStore(tempDir.resolve("source"));
        source.saveVaultHeader(header());
        source.saveSecretRecord(record(secretId(2L), "alpha", 1L));

        BackupArchive archive = backup.export(source, VAULT_ID);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        backup.writeTo(archive, out);

        String entryName = "records/00000000-0000-0000-0000-000000000002.properties";
        String originalEntry = zipEntryText(out.toByteArray(), entryName);
        byte[] tampered =
                replaceZipEntryText(out.toByteArray(), entryName, originalEntry + "\n#tampered\n");
        byte[] reordered = moveManifestToEnd(tampered);

        assertThrows(
                ValidationException.class,
                () -> backup.readFrom(new ByteArrayInputStream(reordered)));
    }

    @Test
    void readFromRejectsRecordEntryMissingDigestInDigestedManifest() throws Exception {
        FileVaultStore source = new FileVaultStore(tempDir.resolve("source"));
        source.saveVaultHeader(header());
        source.saveSecretRecord(record(secretId(2L), "alpha", 1L));

        BackupArchive archive = backup.export(source, VAULT_ID);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        backup.writeTo(archive, out);

        String entryName = "records/00000000-0000-0000-0000-000000000002.properties";
        byte[] missingDigest = removeManifestDigest(out.toByteArray(), "entry.sha256." + entryName);

        assertThrows(
                ValidationException.class,
                () -> backup.readFrom(new ByteArrayInputStream(missingDigest)));
    }

    @Test
    void readFromRejectsTombstoneEntryMissingDigestInDigestedManifest() throws Exception {
        FileVaultStore source = new FileVaultStore(tempDir.resolve("source"));
        source.saveVaultHeader(header());
        source.saveDeletedSecretRecord(deleted(secretId(3L), 2L));

        BackupArchive archive = backup.export(source, VAULT_ID);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        backup.writeTo(archive, out);

        String entryName = "deleted/00000000-0000-0000-0000-000000000003.properties";
        byte[] missingDigest = removeManifestDigest(out.toByteArray(), "entry.sha256." + entryName);

        assertThrows(
                ValidationException.class,
                () -> backup.readFrom(new ByteArrayInputStream(missingDigest)));
    }

    @Test
    void readFromRejectsVaultHeaderEntryMissingDigestInDigestedManifest() throws Exception {
        FileVaultStore source = new FileVaultStore(tempDir.resolve("source"));
        source.saveVaultHeader(header());
        source.saveSecretRecord(record(secretId(2L), "alpha", 1L));

        BackupArchive archive = backup.export(source, VAULT_ID);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        backup.writeTo(archive, out);

        byte[] missingDigest =
                removeManifestDigest(out.toByteArray(), "entry.sha256.vault.properties");

        assertThrows(
                ValidationException.class,
                () -> backup.readFrom(new ByteArrayInputStream(missingDigest)));
    }

    @Test
    void readFromRejectsExtraRecordEntryMissingDigestInDigestedManifest() throws Exception {
        FileVaultStore source = new FileVaultStore(tempDir.resolve("source"));
        source.saveVaultHeader(header());
        source.saveSecretRecord(record(secretId(2L), "alpha", 1L));

        BackupArchive archive = backup.export(source, VAULT_ID);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        backup.writeTo(archive, out);

        ByteArrayOutputStream rebuilt = new ByteArrayOutputStream();
        try (ZipInputStream in = new ZipInputStream(new ByteArrayInputStream(out.toByteArray()));
                ZipOutputStream zip = new ZipOutputStream(rebuilt)) {
            ZipEntry entry;
            while ((entry = in.getNextEntry()) != null) {
                zip.putNextEntry(new ZipEntry(entry.getName()));
                zip.write(in.readAllBytes());
                zip.closeEntry();
            }
            zip.putNextEntry(
                    new ZipEntry("records/00000000-0000-0000-0000-000000000009.properties"));
            zip.write(
                    "vaultId=00000000-0000-0000-0000-000000000001\n"
                            .getBytes(StandardCharsets.UTF_8));
            zip.closeEntry();
        }

        assertThrows(
                ValidationException.class,
                () -> backup.readFrom(new ByteArrayInputStream(rebuilt.toByteArray())));
    }

    @Test
    void readFromRejectsExtraTombstoneEntryMissingDigestInDigestedManifest() throws Exception {
        FileVaultStore source = new FileVaultStore(tempDir.resolve("source"));
        source.saveVaultHeader(header());
        source.saveDeletedSecretRecord(deleted(secretId(3L), 2L));

        BackupArchive archive = backup.export(source, VAULT_ID);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        backup.writeTo(archive, out);

        ByteArrayOutputStream rebuilt = new ByteArrayOutputStream();
        try (ZipInputStream in = new ZipInputStream(new ByteArrayInputStream(out.toByteArray()));
                ZipOutputStream zip = new ZipOutputStream(rebuilt)) {
            ZipEntry entry;
            while ((entry = in.getNextEntry()) != null) {
                zip.putNextEntry(new ZipEntry(entry.getName()));
                zip.write(in.readAllBytes());
                zip.closeEntry();
            }
            zip.putNextEntry(
                    new ZipEntry("deleted/00000000-0000-0000-0000-000000000009.properties"));
            zip.write(
                    """
                    vaultId=00000000-0000-0000-0000-000000000001
                    secretId=00000000-0000-0000-0000-000000000009
                    """
                            .getBytes(StandardCharsets.UTF_8));
            zip.closeEntry();
        }

        assertThrows(
                ValidationException.class,
                () -> backup.readFrom(new ByteArrayInputStream(rebuilt.toByteArray())));
    }

    @Test
    void readFromRejectsManifestDigestForMissingEntry() throws Exception {
        FileVaultStore source = new FileVaultStore(tempDir.resolve("source"));
        source.saveVaultHeader(header());
        source.saveSecretRecord(record(secretId(2L), "alpha", 1L));

        BackupArchive archive = backup.export(source, VAULT_ID);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        backup.writeTo(archive, out);

        byte[] danglingDigest =
                addManifestDigest(
                        out.toByteArray(),
                        "entry.sha256.records/00000000-0000-0000-0000-000000000009.properties",
                        "not-a-real-digest");

        assertThrows(
                ValidationException.class,
                () -> backup.readFrom(new ByteArrayInputStream(danglingDigest)));
    }

    @Test
    void readFromSkipsMalformedEntriesWithoutLosingValidOnes() throws Exception {
        FileVaultStore source = new FileVaultStore(tempDir.resolve("source"));
        source.saveVaultHeader(header());
        source.saveSecretRecord(record(secretId(2L), "alpha", 1L));
        source.saveSecretRecord(record(secretId(3L), "beta", 2L));

        BackupArchive archive = backup.export(source, VAULT_ID);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        backup.writeTo(archive, out);

        // Copy every valid entry, then inject one malformed record entry.
        ByteArrayOutputStream rebuilt = new ByteArrayOutputStream();
        try (ZipInputStream in = new ZipInputStream(new ByteArrayInputStream(out.toByteArray()));
                ZipOutputStream zip = new ZipOutputStream(rebuilt)) {
            ZipEntry entry;
            while ((entry = in.getNextEntry()) != null) {
                zip.putNextEntry(new ZipEntry(entry.getName()));
                zip.write(in.readAllBytes());
                zip.closeEntry();
            }
            zip.putNextEntry(
                    new ZipEntry("records/00000000-0000-0000-0000-000000000009.properties"));
            zip.write(
                    "vaultId=00000000-0000-0000-0000-000000000001\n"
                            .getBytes(StandardCharsets.UTF_8));
            zip.closeEntry();
        }

        byte[] legacyArchive = removeManifestDigests(rebuilt.toByteArray());

        BackupReadResult read = backup.readFrom(new ByteArrayInputStream(legacyArchive));
        assertEquals(1, read.unsupported());
        assertEquals(2, read.archive().records().size());

        FileVaultStore target = new FileVaultStore(tempDir.resolve("target"));
        BackupImportReport report = backup.restore(target, read.archive());
        assertEquals(2, report.imported());
    }

    @Test
    void readFromSkipsDigestedUnsupportedRecordWithoutLosingValidOnes() throws Exception {
        FileVaultStore source = new FileVaultStore(tempDir.resolve("source"));
        source.saveVaultHeader(header());
        source.saveSecretRecord(record(secretId(2L), "alpha", 1L));
        source.saveSecretRecord(record(secretId(3L), "beta", 2L));

        BackupArchive archive = backup.export(source, VAULT_ID);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        backup.writeTo(archive, out);

        String entryName = "records/00000000-0000-0000-0000-000000000002.properties";
        String unsupportedRecord =
                zipEntryText(out.toByteArray(), entryName)
                        .replace("metadata.type=LOGIN_PASSWORD", "metadata.type=FUTURE_SECRET");
        byte[] tampered = replaceZipEntryText(out.toByteArray(), entryName, unsupportedRecord);
        byte[] redigested =
                addManifestDigest(
                        tampered,
                        "entry.sha256." + entryName,
                        sha256(unsupportedRecord.getBytes(StandardCharsets.UTF_8)));

        BackupReadResult read = backup.readFrom(new ByteArrayInputStream(redigested));

        assertEquals(1, read.unsupported());
        assertEquals(1, read.archive().records().size());
        assertEquals(1, read.archive().manifest().recordCount());

        FileVaultStore target = new FileVaultStore(tempDir.resolve("target"));
        BackupImportReport report = backup.restore(target, read.archive());
        assertEquals(1, report.imported());
    }

    @Test
    void archiveRejectsManifestRecordCountMismatch() {
        BackupManifest manifest =
                new BackupManifest(
                        VaultBackupService.FORMAT_VERSION, VAULT_ID, 2, 0, CLOCK.instant());

        ValidationException exception =
                assertThrows(
                        ValidationException.class,
                        () ->
                                new BackupArchive(
                                        manifest,
                                        header(),
                                        List.of(record(secretId(2L), "alpha", 1L)),
                                        List.of()));

        assertTrue(exception.getMessage().contains("record count"));
    }

    @Test
    void archiveRejectsUnsupportedFutureFormatVersion() {
        BackupManifest manifest =
                new BackupManifest(
                        VaultBackupService.FORMAT_VERSION + 1, VAULT_ID, 0, 0, CLOCK.instant());

        ValidationException exception =
                assertThrows(
                        ValidationException.class,
                        () -> new BackupArchive(manifest, header(), List.of(), List.of()));

        assertTrue(exception.getMessage().contains("format version"));
    }

    @Test
    void archiveRejectsRecordFromAnotherVault() {
        VaultId otherVault = new VaultId(new UUID(0L, 99L));
        EncryptedSecretRecord foreignRecord =
                new EncryptedSecretRecord(
                        otherVault,
                        record(secretId(2L), "alpha", 1L).metadata(),
                        record(secretId(2L), "alpha", 1L).payload(),
                        1L);

        ValidationException exception =
                assertThrows(
                        ValidationException.class,
                        () ->
                                new BackupArchive(
                                        new BackupManifest(
                                                VaultBackupService.FORMAT_VERSION,
                                                VAULT_ID,
                                                1,
                                                0,
                                                CLOCK.instant()),
                                        header(),
                                        List.of(foreignRecord),
                                        List.of()));

        assertTrue(exception.getMessage().contains("vault"));
    }

    @Test
    void archiveRejectsDuplicateRecordPrimaryKey() {
        SecretId secretId = secretId(2L);
        ValidationException exception =
                assertThrows(
                        ValidationException.class,
                        () ->
                                new BackupArchive(
                                        new BackupManifest(
                                                VaultBackupService.FORMAT_VERSION,
                                                VAULT_ID,
                                                2,
                                                0,
                                                CLOCK.instant()),
                                        header(),
                                        List.of(
                                                record(secretId, "alpha", 1L),
                                                record(secretId, "beta", 2L)),
                                        List.of()));

        assertTrue(exception.getMessage().contains("duplicate record"));
    }

    @Test
    void archiveRejectsDuplicateTombstonePrimaryKey() {
        SecretId secretId = secretId(2L);
        ValidationException exception =
                assertThrows(
                        ValidationException.class,
                        () ->
                                new BackupArchive(
                                        new BackupManifest(
                                                VaultBackupService.FORMAT_VERSION,
                                                VAULT_ID,
                                                0,
                                                2,
                                                CLOCK.instant()),
                                        header(),
                                        List.of(),
                                        List.of(deleted(secretId, 1L), deleted(secretId, 2L))));

        assertTrue(exception.getMessage().contains("duplicate tombstone"));
    }

    @Test
    void archiveRejectsActiveAndTombstoneForSamePrimaryKey() {
        SecretId secretId = secretId(2L);
        ValidationException exception =
                assertThrows(
                        ValidationException.class,
                        () ->
                                new BackupArchive(
                                        new BackupManifest(
                                                VaultBackupService.FORMAT_VERSION,
                                                VAULT_ID,
                                                1,
                                                1,
                                                CLOCK.instant()),
                                        header(),
                                        List.of(record(secretId, "alpha", 1L)),
                                        List.of(deleted(secretId, 2L))));

        assertTrue(exception.getMessage().contains("active and tombstone"));
    }

    private static VaultHeader header() {
        return new VaultHeader(
                VAULT_ID,
                1,
                "PBKDF2WithHmacSHA256",
                new byte[] {1, 2, 3},
                120_000,
                new KeyId("vault-key"),
                new byte[] {4, 5, 6},
                Instant.parse("2026-07-02T00:00:00Z"),
                Instant.parse("2026-07-02T00:01:00Z"));
    }

    private static SecretId secretId(long suffix) {
        return new SecretId(new UUID(0L, suffix));
    }

    private static EncryptedSecretRecord record(SecretId id, String title, long revision) {
        SecretMetadata metadata =
                new SecretMetadata(
                        id,
                        SecretType.LOGIN_PASSWORD,
                        title,
                        Set.of("work"),
                        Instant.parse("2026-07-02T00:00:00Z"),
                        Instant.parse("2026-07-02T00:01:00Z"),
                        revision);
        EncryptedEnvelope envelope =
                new EncryptedEnvelope(
                        1,
                        "AES-256-GCM",
                        new KeyId("vault-key"),
                        new byte[] {1, 2, 3},
                        SecretRecordAad.encode(VAULT_ID, metadata, revision),
                        new byte[] {7, 8, 9},
                        Instant.parse("2026-07-02T00:02:00Z"));
        return new EncryptedSecretRecord(VAULT_ID, metadata, envelope, revision);
    }

    private static DeletedSecretRecord deleted(SecretId id, long revision) {
        return new DeletedSecretRecord(
                VAULT_ID,
                id,
                SecretType.LOGIN_PASSWORD,
                revision,
                Instant.parse("2026-07-02T00:03:00Z"));
    }

    private static String zipEntryText(byte[] archive, String entryName) throws Exception {
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(archive))) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                if (entry.getName().equals(entryName)) {
                    return new String(zip.readAllBytes(), StandardCharsets.UTF_8);
                }
            }
        }
        throw new AssertionError("Missing zip entry: " + entryName);
    }

    private static byte[] replaceZipEntryText(byte[] archive, String entryName, String replacement)
            throws Exception {
        ByteArrayOutputStream rebuilt = new ByteArrayOutputStream();
        try (ZipInputStream in = new ZipInputStream(new ByteArrayInputStream(archive));
                ZipOutputStream zip = new ZipOutputStream(rebuilt)) {
            ZipEntry entry;
            boolean replaced = false;
            while ((entry = in.getNextEntry()) != null) {
                zip.putNextEntry(new ZipEntry(entry.getName()));
                if (entry.getName().equals(entryName)) {
                    zip.write(replacement.getBytes(StandardCharsets.UTF_8));
                    replaced = true;
                } else {
                    zip.write(in.readAllBytes());
                }
                zip.closeEntry();
            }
            if (!replaced) {
                throw new AssertionError("Missing zip entry: " + entryName);
            }
        }
        return rebuilt.toByteArray();
    }

    private static byte[] removeManifestDigest(byte[] archive, String digestKey) throws Exception {
        Properties manifest = new Properties();
        manifest.load(new java.io.StringReader(zipEntryText(archive, "manifest.properties")));
        manifest.remove(digestKey);
        ByteArrayOutputStream manifestBytes = new ByteArrayOutputStream();
        manifest.store(new java.io.OutputStreamWriter(manifestBytes, StandardCharsets.UTF_8), null);
        return replaceZipEntryText(
                archive, "manifest.properties", manifestBytes.toString(StandardCharsets.UTF_8));
    }

    private static byte[] addManifestDigest(byte[] archive, String digestKey, String digest)
            throws Exception {
        Properties manifest = new Properties();
        manifest.load(new java.io.StringReader(zipEntryText(archive, "manifest.properties")));
        manifest.setProperty(digestKey, digest);
        ByteArrayOutputStream manifestBytes = new ByteArrayOutputStream();
        manifest.store(new java.io.OutputStreamWriter(manifestBytes, StandardCharsets.UTF_8), null);
        return replaceZipEntryText(
                archive, "manifest.properties", manifestBytes.toString(StandardCharsets.UTF_8));
    }

    private static byte[] removeManifestDigests(byte[] archive) throws Exception {
        Properties manifest = new Properties();
        manifest.load(new java.io.StringReader(zipEntryText(archive, "manifest.properties")));
        manifest.stringPropertyNames().stream()
                .filter(name -> name.startsWith("entry.sha256."))
                .toList()
                .forEach(manifest::remove);
        ByteArrayOutputStream manifestBytes = new ByteArrayOutputStream();
        manifest.store(new java.io.OutputStreamWriter(manifestBytes, StandardCharsets.UTF_8), null);
        return replaceZipEntryText(
                archive, "manifest.properties", manifestBytes.toString(StandardCharsets.UTF_8));
    }

    private static byte[] moveManifestToEnd(byte[] archive) throws Exception {
        ByteArrayOutputStream rebuilt = new ByteArrayOutputStream();
        byte[] manifest = null;
        try (ZipInputStream in = new ZipInputStream(new ByteArrayInputStream(archive));
                ZipOutputStream zip = new ZipOutputStream(rebuilt)) {
            ZipEntry entry;
            while ((entry = in.getNextEntry()) != null) {
                byte[] bytes = in.readAllBytes();
                if (entry.getName().equals("manifest.properties")) {
                    manifest = bytes;
                } else {
                    zip.putNextEntry(new ZipEntry(entry.getName()));
                    zip.write(bytes);
                    zip.closeEntry();
                }
            }
            if (manifest == null) {
                throw new AssertionError("Missing zip entry: manifest.properties");
            }
            zip.putNextEntry(new ZipEntry("manifest.properties"));
            zip.write(manifest);
            zip.closeEntry();
        }
        return rebuilt.toByteArray();
    }

    private static String sha256(byte[] bytes) throws Exception {
        return Base64.getEncoder()
                .encodeToString(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
}
