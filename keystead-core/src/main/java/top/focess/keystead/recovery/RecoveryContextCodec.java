package top.focess.keystead.recovery;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.memory.Wipe;

/** Versioned encodings for recovery vault-key wrapping contexts. */
final class RecoveryContextCodec {

    private static final byte[] VERSION_2_MAGIC = {'K', 'R', 'C', '2'};
    private static final int MAX_TEXT_FIELD_BYTES = 64 * 1024;

    private RecoveryContextCodec() {}

    /**
     * Encodes the v2 recovery wrapping context, binding the wrapped vault key to the account, vault
     * fingerprint, enrollment, generation, and target key id.
     *
     * <p>The vault fingerprint (a non-secret, passphrase-derived routing identity, carried as a hex
     * string) replaces the v0.2 vault id as the vault-identity field.
     *
     * @param username the account username
     * @param fingerprint the vault fingerprint as a hex string
     * @param enrollmentId the recovery enrollment identifier
     * @param generation the enrollment generation; must be positive
     * @param keyId the id of the wrapped vault key
     * @return the encoded context bytes
     */
    static byte @NonNull [] version2(
            @NonNull String username,
            @NonNull String fingerprint,
            @NonNull String enrollmentId,
            long generation,
            @NonNull String keyId) {
        requirePositiveGeneration(generation);
        byte @Nullable [] encodedUsername = null;
        byte @Nullable [] encodedFingerprint = null;
        byte @Nullable [] encodedEnrollmentId = null;
        byte @Nullable [] encodedKeyId = null;
        byte @Nullable [] output = null;
        boolean completed = false;
        try {
            encodedUsername = encodeText(username);
            encodedFingerprint = encodeText(fingerprint);
            encodedEnrollmentId = encodeText(enrollmentId);
            encodedKeyId = encodeText(keyId);
            int outputLength =
                    VERSION_2_MAGIC.length
                            + Integer.BYTES * 4
                            + encodedUsername.length
                            + encodedFingerprint.length
                            + encodedEnrollmentId.length
                            + Long.BYTES
                            + encodedKeyId.length;
            output = new byte[outputLength];
            ByteBuffer.wrap(output)
                    .put(VERSION_2_MAGIC)
                    .putInt(encodedUsername.length)
                    .put(encodedUsername)
                    .putInt(encodedFingerprint.length)
                    .put(encodedFingerprint)
                    .putInt(encodedEnrollmentId.length)
                    .put(encodedEnrollmentId)
                    .putLong(generation)
                    .putInt(encodedKeyId.length)
                    .put(encodedKeyId);
            completed = true;
            return output;
        } finally {
            Wipe.wipe(encodedUsername);
            Wipe.wipe(encodedFingerprint);
            Wipe.wipe(encodedEnrollmentId);
            Wipe.wipe(encodedKeyId);
            if (!completed) {
                Wipe.wipe(output);
            }
        }
    }

    private static byte @NonNull [] encodeText(@NonNull String value) {
        Objects.requireNonNull(value, "value");
        if (value.length() > MAX_TEXT_FIELD_BYTES) {
            throw new IllegalArgumentException(
                    "Recovery context text field exceeds the size limit");
        }
        var encoder =
                StandardCharsets.UTF_8
                        .newEncoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT);
        int workspaceLength = (int) Math.ceil(value.length() * encoder.maxBytesPerChar());
        byte[] workspace = new byte[workspaceLength];
        try {
            ByteBuffer encoded = ByteBuffer.wrap(workspace);
            var result = encoder.encode(CharBuffer.wrap(value), encoded, true);
            if (result.isError()) {
                result.throwException();
            }
            result = encoder.flush(encoded);
            if (result.isError()) {
                result.throwException();
            }
            if (encoded.position() > MAX_TEXT_FIELD_BYTES) {
                throw new IllegalArgumentException(
                        "Recovery context text field exceeds the size limit");
            }
            return Arrays.copyOf(workspace, encoded.position());
        } catch (CharacterCodingException error) {
            throw new IllegalArgumentException(
                    "Recovery context text field is not valid UTF-8", error);
        } finally {
            Wipe.wipe(workspace);
        }
    }

    private static void requirePositiveGeneration(long generation) {
        if (generation <= 0) {
            throw new IllegalArgumentException("Recovery generation must be positive");
        }
    }
}
