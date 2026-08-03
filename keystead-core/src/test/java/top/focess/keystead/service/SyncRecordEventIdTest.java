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
                    false);

    @Test
    void contentHashUsesTheStableCrossPlatformEncoding() {
        assertEquals("47fiwy3Hb3dBWDTsn7mEnwW_i2IvfjIgDvvpXWzOGCU", SyncRecordEventId.of(RECORD));
    }

    @Test
    void contentHashBindsEveryEncryptedRecordField() {
        String expected = SyncRecordEventId.of(RECORD);

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
                                RECORD.deleted())));
        assertNotEquals(
                expected,
                SyncRecordEventId.of(
                        new EncryptedSyncRecord(
                                RECORD.fingerprint(),
                                RECORD.secretId(),
                                RECORD.revision(),
                                RECORD.secretType(),
                                RECORD.encryptedProfile(),
                                "changed",
                                RECORD.deleted())));
    }
}
