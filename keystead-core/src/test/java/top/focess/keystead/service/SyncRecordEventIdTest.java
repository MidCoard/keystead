package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.Test;

class SyncRecordEventIdTest {

    private static final EncryptedSyncRecord RECORD =
            new EncryptedSyncRecord(
                    "6000000000000001",
                    "550e8400-e29b-41d4-a716-446655440000",
                    7,
                    "LOGIN_PASSWORD",
                    "profile",
                    "payload",
                    false,
                    "content-key");

    @Test
    void contentHashUsesTheStableCrossPlatformEncoding() {
        assertEquals("ac6hbddox4BkPm4eukfXjPBspNdI9c-J4MOaOB2fs6g", SyncRecordEventId.of(RECORD));
    }

    @Test
    void contentHashIgnoresCiphertextBecauseReexportRefreshesNonces() {
        String expected = SyncRecordEventId.of(RECORD);

        assertEquals(
                expected,
                SyncRecordEventId.of(
                        new EncryptedSyncRecord(
                                RECORD.fingerprint(),
                                RECORD.secretId(),
                                RECORD.revision(),
                                RECORD.secretType(),
                                "reencrypted-profile",
                                "reencrypted-payload",
                                RECORD.deleted(),
                                RECORD.contentKey())));
    }

    @Test
    void contentHashBindsEveryIdentityFieldAndTheContentKey() {
        String expected = SyncRecordEventId.of(RECORD);

        assertNotEquals(
                expected,
                SyncRecordEventId.of(
                        new EncryptedSyncRecord(
                                "6000000000000002",
                                RECORD.secretId(),
                                RECORD.revision(),
                                RECORD.secretType(),
                                RECORD.encryptedProfile(),
                                RECORD.envelope(),
                                RECORD.deleted(),
                                RECORD.contentKey())));
        assertNotEquals(
                expected,
                SyncRecordEventId.of(
                        new EncryptedSyncRecord(
                                RECORD.fingerprint(),
                                "550e8400-e29b-41d4-a716-446655440001",
                                RECORD.revision(),
                                RECORD.secretType(),
                                RECORD.encryptedProfile(),
                                RECORD.envelope(),
                                RECORD.deleted(),
                                RECORD.contentKey())));
        assertNotEquals(
                expected,
                SyncRecordEventId.of(
                        new EncryptedSyncRecord(
                                RECORD.fingerprint(),
                                RECORD.secretId(),
                                RECORD.revision() + 1,
                                RECORD.secretType(),
                                RECORD.encryptedProfile(),
                                RECORD.envelope(),
                                RECORD.deleted(),
                                RECORD.contentKey())));
        assertNotEquals(
                expected,
                SyncRecordEventId.of(
                        new EncryptedSyncRecord(
                                RECORD.fingerprint(),
                                RECORD.secretId(),
                                RECORD.revision(),
                                "SECURE_NOTE",
                                RECORD.encryptedProfile(),
                                RECORD.envelope(),
                                RECORD.deleted(),
                                RECORD.contentKey())));
        assertNotEquals(
                expected,
                SyncRecordEventId.of(
                        new EncryptedSyncRecord(
                                RECORD.fingerprint(),
                                RECORD.secretId(),
                                RECORD.revision(),
                                RECORD.secretType(),
                                RECORD.encryptedProfile(),
                                "",
                                true,
                                RECORD.contentKey())));
        assertNotEquals(
                expected,
                SyncRecordEventId.of(
                        new EncryptedSyncRecord(
                                RECORD.fingerprint(),
                                RECORD.secretId(),
                                RECORD.revision(),
                                RECORD.secretType(),
                                RECORD.encryptedProfile(),
                                RECORD.envelope(),
                                RECORD.deleted(),
                                "changed-content-key")));
    }
}
