package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.junit.jupiter.api.Test;
import top.focess.keystead.model.DeletedSecretRecord;
import top.focess.keystead.model.EncryptedEnvelope;
import top.focess.keystead.model.EncryptedSecretRecord;
import top.focess.keystead.model.KeyId;
import top.focess.keystead.model.SecretId;
import top.focess.keystead.model.SecretMetadata;
import top.focess.keystead.model.SecretRecordAad;
import top.focess.keystead.model.SecretType;
import top.focess.keystead.model.VaultHeader;
import top.focess.keystead.model.VaultId;

class BackupArchiveCodecWriterLimitTest {

    private static final int MAX_ENTRY_BYTES = 1_048_576;
    private static final int MAX_ENTRY_COUNT = 4_096;
    private static final int MAX_ARCHIVE_BYTES = 16 * 1_024 * 1_024;
    private static final Instant CREATED_AT = Instant.parse("2026-07-02T00:00:00Z");
    private static final Instant UPDATED_AT = Instant.parse("2026-07-02T00:01:00Z");
    private static final Instant ENCRYPTED_AT = Instant.parse("2026-07-02T00:02:00Z");
    private static final VaultId VAULT_ID = new VaultId(new UUID(0L, 1L));

    @Test
    void writerRoundTripsRecordAtExactSerializedEntryLimit() throws Exception {
        EncryptedSecretRecord record = recordAtSerializedSize(secretId(2L), MAX_ENTRY_BYTES);
        BackupArchive archive = archive(header(new byte[] {4, 5, 6}), List.of(record), List.of());

        byte[] encoded = write(archive);
        BackupReadResult read = BackupArchiveCodec.read(new ByteArrayInputStream(encoded));

        assertEquals(MAX_ENTRY_BYTES, zipEntrySize(encoded, recordEntryName(record)));
        assertEquals(1, read.archive().records().size());
        assertArrayEquals(
                record.payload().ciphertext(),
                read.archive().records().getFirst().payload().ciphertext());
    }

    @Test
    void writerRejectsRecordOneSerializedByteOverLimitBeforePublishingOutput() throws Exception {
        EncryptedSecretRecord exact = recordAtSerializedSize(secretId(2L), MAX_ENTRY_BYTES);
        EncryptedSecretRecord oversized = withAlgorithm(exact, exact.payload().algorithm() + "X");
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        ValidationException failure =
                assertThrows(
                        ValidationException.class,
                        () ->
                                BackupArchiveCodec.write(
                                        archive(
                                                header(new byte[] {4, 5, 6}),
                                                List.of(oversized),
                                                List.of()),
                                        output));

        assertEquals("Backup entry exceeds size limit", failure.getMessage());
        assertEquals(0, output.size());
        assertFalse(failure.getMessage().contains(recordEntryName(oversized)));
        assertFalse(failure.getMessage().contains(oversized.payload().algorithm()));
    }

    @Test
    void writerRoundTripsHeaderAtExactSerializedEntryLimit() throws Exception {
        VaultHeader header = headerAtSerializedSize(MAX_ENTRY_BYTES);
        BackupArchive archive = archive(header, List.of(), List.of());

        byte[] encoded = write(archive);
        BackupReadResult read = BackupArchiveCodec.read(new ByteArrayInputStream(encoded));

        assertEquals(MAX_ENTRY_BYTES, zipEntrySize(encoded, "vault.properties"));
        assertArrayEquals(header.wrappedVaultKey(), read.archive().vaultHeader().wrappedVaultKey());
    }

    @Test
    void writerRejectsHeaderOneSerializedByteOverLimitBeforePublishingOutput() throws Exception {
        VaultHeader exact = headerAtSerializedSize(MAX_ENTRY_BYTES);
        VaultHeader oversized =
                new VaultHeader(
                        VAULT_ID,
                        1,
                        exact.kdfAlgorithm() + "X",
                        exact.kdfSalt(),
                        exact.kdfIterations(),
                        exact.vaultKeyId(),
                        exact.wrappedVaultKey(),
                        CREATED_AT,
                        UPDATED_AT);
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        ValidationException failure =
                assertThrows(
                        ValidationException.class,
                        () ->
                                BackupArchiveCodec.write(
                                        archive(oversized, List.of(), List.of()), output));

        assertEquals("Backup entry exceeds size limit", failure.getMessage());
        assertEquals(0, output.size());
        assertFalse(failure.getMessage().contains("vault.properties"));
        assertFalse(failure.getMessage().contains(oversized.kdfAlgorithm()));
    }

    @Test
    void writerAcceptsExactEntryCountAndRejectsFirstOverBeforePublishingOutput() {
        List<DeletedSecretRecord> exactTombstones = tombstones(MAX_ENTRY_COUNT - 2);
        byte[] encoded = write(archive(header(new byte[] {4, 5, 6}), List.of(), exactTombstones));

        assertEquals(MAX_ENTRY_COUNT, zipEntryCount(encoded));
        assertEquals(
                exactTombstones.size(),
                BackupArchiveCodec.read(new ByteArrayInputStream(encoded))
                        .archive()
                        .tombstones()
                        .size());

        List<DeletedSecretRecord> oversizedTombstones =
                new ArrayList<>(tombstones(MAX_ENTRY_COUNT - 1));
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        ValidationException failure =
                assertThrows(
                        ValidationException.class,
                        () ->
                                BackupArchiveCodec.write(
                                        archive(
                                                header(new byte[] {4, 5, 6}),
                                                List.of(),
                                                oversizedTombstones),
                                        output));

        assertEquals("Backup archive entry count exceeds limit", failure.getMessage());
        assertEquals(0, output.size());
    }

    @Test
    void writerAcceptsExactAggregateSizeAndRejectsFirstOverBeforePublishingOutput()
            throws Exception {
        List<EncryptedSecretRecord> records = new ArrayList<>();
        for (int index = 0; index < 15; index++) {
            records.add(recordAtSerializedSize(secretId(index + 2L), MAX_ENTRY_BYTES));
        }
        SecretId finalId = secretId(100L);
        records.add(record(finalId, 3, "A"));
        BackupArchive calibration = archive(header(new byte[] {4, 5, 6}), records, List.of());
        byte[] calibrationBytes = write(calibration);
        int missingBytes = MAX_ARCHIVE_BYTES - zipExpandedSize(calibrationBytes);
        int finalSize = zipEntrySize(calibrationBytes, recordEntryName(records.getLast()));
        records.set(records.size() - 1, recordAtSerializedSize(finalId, finalSize + missingBytes));
        BackupArchive exact = archive(header(new byte[] {4, 5, 6}), records, List.of());

        byte[] encoded = write(exact);
        assertEquals(MAX_ARCHIVE_BYTES, zipExpandedSize(encoded));
        assertEquals(
                records.size(),
                BackupArchiveCodec.read(new ByteArrayInputStream(encoded))
                        .archive()
                        .records()
                        .size());

        List<EncryptedSecretRecord> oversizedRecords = new ArrayList<>(records);
        EncryptedSecretRecord last = oversizedRecords.getLast();
        oversizedRecords.set(
                oversizedRecords.size() - 1, withAlgorithm(last, last.payload().algorithm() + "X"));
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        ValidationException failure =
                assertThrows(
                        ValidationException.class,
                        () ->
                                BackupArchiveCodec.write(
                                        archive(
                                                header(new byte[] {4, 5, 6}),
                                                oversizedRecords,
                                                List.of()),
                                        output));

        assertEquals("Backup archive exceeds size limit", failure.getMessage());
        assertEquals(0, output.size());
    }

    private static EncryptedSecretRecord recordAtSerializedSize(SecretId id, int targetBytes)
            throws Exception {
        EncryptedSecretRecord calibration = record(id, 3, "A");
        byte[] encoded =
                write(archive(header(new byte[] {4, 5, 6}), List.of(calibration), List.of()));
        int currentBytes = zipEntrySize(encoded, recordEntryName(calibration));
        int growth = targetBytes - currentBytes;
        if (growth < 0) {
            throw new AssertionError("Target entry size is below the record fixture overhead");
        }
        int ciphertextGrowth = (growth / 4) * 3;
        int algorithmGrowth = growth % 4;
        return record(id, 3 + ciphertextGrowth, "A" + "X".repeat(algorithmGrowth));
    }

    private static VaultHeader headerAtSerializedSize(int targetBytes) throws Exception {
        VaultHeader calibration = header(new byte[3], "A");
        byte[] encoded = write(archive(calibration, List.of(), List.of()));
        int currentBytes = zipEntrySize(encoded, "vault.properties");
        int growth = targetBytes - currentBytes;
        if (growth < 0) {
            throw new AssertionError("Target entry size is below the header fixture overhead");
        }
        int packageGrowth = (growth / 4) * 3;
        int algorithmGrowth = growth % 4;
        return header(new byte[3 + packageGrowth], "A" + "X".repeat(algorithmGrowth));
    }

    private static BackupArchive archive(
            VaultHeader header,
            List<EncryptedSecretRecord> records,
            List<DeletedSecretRecord> tombstones) {
        return new BackupArchive(
                new BackupManifest(1, VAULT_ID, records.size(), tombstones.size(), CREATED_AT),
                header,
                records,
                tombstones);
    }

    private static VaultHeader header(byte[] wrappedVaultKey) {
        return header(wrappedVaultKey, "PBKDF2WithHmacSHA256");
    }

    private static VaultHeader header(byte[] wrappedVaultKey, String kdfAlgorithm) {
        return new VaultHeader(
                VAULT_ID,
                1,
                kdfAlgorithm,
                new byte[] {1, 2, 3},
                120_000,
                new KeyId("vault-key"),
                wrappedVaultKey,
                CREATED_AT,
                UPDATED_AT);
    }

    private static EncryptedSecretRecord record(
            SecretId id, int ciphertextBytes, String algorithm) {
        SecretMetadata metadata =
                new SecretMetadata(
                        id,
                        SecretType.LOGIN_PASSWORD,
                        "title",
                        Set.of("work"),
                        CREATED_AT,
                        UPDATED_AT,
                        1L);
        EncryptedEnvelope envelope =
                new EncryptedEnvelope(
                        1,
                        algorithm,
                        new KeyId("vault-key"),
                        new byte[] {1, 2, 3},
                        SecretRecordAad.encode(VAULT_ID, metadata, 1L),
                        new byte[ciphertextBytes],
                        ENCRYPTED_AT);
        return new EncryptedSecretRecord(VAULT_ID, metadata, envelope, 1L);
    }

    private static EncryptedSecretRecord withAlgorithm(
            EncryptedSecretRecord record, String algorithm) {
        EncryptedEnvelope payload = record.payload();
        EncryptedEnvelope replacement =
                new EncryptedEnvelope(
                        payload.version(),
                        algorithm,
                        payload.keyId(),
                        payload.nonce(),
                        payload.aad(),
                        payload.ciphertext(),
                        payload.encryptedAt());
        return new EncryptedSecretRecord(
                record.vaultId(), record.metadata(), replacement, record.revision());
    }

    private static List<DeletedSecretRecord> tombstones(int count) {
        List<DeletedSecretRecord> tombstones = new ArrayList<>(count);
        for (int index = 0; index < count; index++) {
            tombstones.add(
                    new DeletedSecretRecord(
                            VAULT_ID,
                            secretId(index + 2L),
                            SecretType.LOGIN_PASSWORD,
                            1L,
                            ENCRYPTED_AT));
        }
        return tombstones;
    }

    private static SecretId secretId(long suffix) {
        return new SecretId(new UUID(0L, suffix));
    }

    private static String recordEntryName(EncryptedSecretRecord record) {
        return "records/" + record.metadata().id().value() + ".properties";
    }

    private static byte[] write(BackupArchive archive) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        BackupArchiveCodec.write(archive, output);
        return output.toByteArray();
    }

    private static int zipEntrySize(byte[] archive, String entryName) throws Exception {
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(archive))) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                byte[] bytes = zip.readAllBytes();
                if (entry.getName().equals(entryName)) {
                    return bytes.length;
                }
            }
        }
        throw new AssertionError("Missing ZIP entry");
    }

    private static int zipEntryCount(byte[] archive) {
        int count = 0;
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(archive))) {
            while (zip.getNextEntry() != null) {
                zip.readAllBytes();
                count++;
            }
        } catch (Exception e) {
            throw new AssertionError("Could not count ZIP entries", e);
        }
        return count;
    }

    private static int zipExpandedSize(byte[] archive) {
        int total = 0;
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(archive))) {
            while (zip.getNextEntry() != null) {
                total += zip.readAllBytes().length;
            }
        } catch (Exception e) {
            throw new AssertionError("Could not measure ZIP entries", e);
        }
        return total;
    }
}
