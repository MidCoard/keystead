package top.focess.keystead.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import top.focess.keystead.model.EncryptedEnvelope;
import top.focess.keystead.model.SecurityLimits;

class SyncRecordCodecLimitTest {

    @Test
    void rejectsPaddedCiphertextOneByteOverLimitBeforeDecoderAllocation() {
        String encoded =
                Base64.getEncoder()
                        .encodeToString(new byte[SecurityLimits.MAX_ENVELOPE_CIPHERTEXT_BYTES + 1]);
        AtomicBoolean decoded = new AtomicBoolean();

        ValidationException failure =
                assertThrows(
                        ValidationException.class,
                        () ->
                                SyncRecordCodec.envelopeWithAad(
                                        envelope(encoded),
                                        new byte[0],
                                        (field, value) -> {
                                            if (field.equals("ciphertext")) {
                                                decoded.set(true);
                                                throw new AssertionError("decoder must not run");
                                            }
                                            return Base64.getDecoder().decode(value);
                                        }));

        assertEquals("Sync record ciphertext exceeds the size limit", failure.getMessage());
        assertEquals(false, decoded.get());
    }

    @Test
    void rejectsUnpaddedCiphertextOneByteOverLimitBeforeDecoderAllocation() {
        String encoded =
                Base64.getEncoder()
                        .withoutPadding()
                        .encodeToString(new byte[SecurityLimits.MAX_ENVELOPE_CIPHERTEXT_BYTES + 1]);

        ValidationException failure =
                assertThrows(
                        ValidationException.class,
                        () ->
                                SyncRecordCodec.envelopeWithAad(
                                        envelope(encoded),
                                        new byte[0],
                                        (field, value) -> {
                                            if (field.equals("ciphertext")) {
                                                throw new AssertionError("decoder must not run");
                                            }
                                            return Base64.getDecoder().decode(value);
                                        }));

        assertEquals("Sync record ciphertext exceeds the size limit", failure.getMessage());
    }

    @Test
    void acceptsExactCiphertextLimitWithPaddedAndUnpaddedBase64() {
        byte[] exact = new byte[SecurityLimits.MAX_ENVELOPE_CIPHERTEXT_BYTES];
        for (Base64.Encoder encoder :
                new Base64.Encoder[] {Base64.getEncoder(), Base64.getEncoder().withoutPadding()}) {
            EncryptedEnvelope envelope =
                    SyncRecordCodec.envelopeWithAad(
                            envelope(encoder.encodeToString(exact)), new byte[0]);
            assertEquals(
                    SecurityLimits.MAX_ENVELOPE_CIPHERTEXT_BYTES, envelope.ciphertext().length);
        }
    }

    @Test
    void rejectsMalformedOverLimitShapeWithRedactedSizeError() {
        String encoded =
                "!"
                        .repeat(
                                Base64.getEncoder()
                                        .encodeToString(
                                                new byte
                                                        [SecurityLimits
                                                                        .MAX_ENVELOPE_CIPHERTEXT_BYTES
                                                                + 1])
                                        .length());

        ValidationException failure =
                assertThrows(
                        ValidationException.class,
                        () -> SyncRecordCodec.envelopeWithAad(envelope(encoded), new byte[0]));

        assertEquals("Sync record ciphertext exceeds the size limit", failure.getMessage());
    }

    private String envelope(String ciphertext) {
        return "version=1\nalgorithm=AES-256-GCM\nkeyId=vault-key\nnonce=AQID\nciphertext="
                + ciphertext
                + "\nencryptedAt="
                + Instant.parse("2026-07-15T00:00:00Z")
                + "\n";
    }
}
