package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import top.focess.keystead.model.SecretId;
import top.focess.keystead.model.SecretMetadata;
import top.focess.keystead.model.SecretType;

class PayloadCodecTest {

    @Test
    void loginPayloadRejectsInvalidNegativeFieldLength() {
        byte[] payload =
                ByteBuffer.allocate(Integer.BYTES * 5)
                        .putInt(1)
                        .putInt(-2)
                        .putInt(-1)
                        .putInt(-1)
                        .putInt(-1)
                        .array();

        assertThrows(
                ValidationException.class,
                () -> LoginPayloadCodec.decode(metadata(SecretType.LOGIN_PASSWORD), payload));
    }

    @Test
    void loginPayloadRejectsTruncatedField() {
        byte[] payload = ByteBuffer.allocate(Integer.BYTES * 2).putInt(1).putInt(128).array();

        assertThrows(
                ValidationException.class,
                () -> LoginPayloadCodec.decode(metadata(SecretType.LOGIN_PASSWORD), payload));
    }

    @Test
    void loginPayloadRejectsTrailingBytes() {
        byte[] payload =
                ByteBuffer.allocate(Integer.BYTES * 5 + 1)
                        .putInt(1)
                        .putInt(-1)
                        .putInt(-1)
                        .putInt(-1)
                        .putInt(-1)
                        .put((byte) 1)
                        .array();

        assertThrows(
                ValidationException.class,
                () -> LoginPayloadCodec.decode(metadata(SecretType.LOGIN_PASSWORD), payload));
    }

    @Test
    void secureNotePayloadRejectsInvalidNegativeFieldLength() {
        byte[] payload = ByteBuffer.allocate(Integer.BYTES * 2).putInt(1).putInt(-2).array();

        assertThrows(
                ValidationException.class,
                () -> SecureNotePayloadCodec.decode(metadata(SecretType.SECURE_NOTE), payload));
    }

    @Test
    void secureNotePayloadRejectsTruncatedField() {
        byte[] payload = ByteBuffer.allocate(Integer.BYTES * 2).putInt(1).putInt(128).array();

        assertThrows(
                ValidationException.class,
                () -> SecureNotePayloadCodec.decode(metadata(SecretType.SECURE_NOTE), payload));
    }

    @Test
    void secureNotePayloadRejectsTrailingBytes() {
        byte[] payload =
                ByteBuffer.allocate(Integer.BYTES * 2 + 1)
                        .putInt(1)
                        .putInt(-1)
                        .put((byte) 1)
                        .array();

        assertThrows(
                ValidationException.class,
                () -> SecureNotePayloadCodec.decode(metadata(SecretType.SECURE_NOTE), payload));
    }

    private static SecretMetadata metadata(SecretType type) {
        return new SecretMetadata(
                new SecretId(UUID.fromString("30000000-0000-0000-0000-000000000001")),
                type,
                "Malformed",
                Set.of(),
                Instant.parse("2026-07-02T00:00:00Z"),
                Instant.parse("2026-07-02T00:00:00Z"),
                1L);
    }
}
