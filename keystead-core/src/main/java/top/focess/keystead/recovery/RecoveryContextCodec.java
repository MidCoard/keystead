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

/** Versioned encodings for recovery vault-key wrapping contexts. */
final class RecoveryContextCodec {

    private static final byte[] VERSION_2_MAGIC = {'K', 'R', 'C', '2'};
    private static final int MAX_TEXT_FIELD_BYTES = 64 * 1024;

    private static final byte[] LEGACY_PREFIX =
            "keystead-recovery-vault-package-v1|user:".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] LEGACY_VAULT = "|vault:".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] LEGACY_ENROLLMENT =
            "|enrollment:".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] LEGACY_GENERATION =
            "|generation:".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] LEGACY_KEY = "|key:".getBytes(StandardCharsets.US_ASCII);

    private RecoveryContextCodec() {}

    static byte @NonNull [] version2(
            @NonNull String username,
            @NonNull String vaultId,
            @NonNull String enrollmentId,
            long generation,
            @NonNull String keyId) {
        requirePositiveGeneration(generation);
        byte @Nullable [] encodedUsername = null;
        byte @Nullable [] encodedVaultId = null;
        byte @Nullable [] encodedEnrollmentId = null;
        byte @Nullable [] encodedKeyId = null;
        byte @Nullable [] output = null;
        boolean completed = false;
        try {
            encodedUsername = encodeText(username);
            encodedVaultId = encodeText(vaultId);
            encodedEnrollmentId = encodeText(enrollmentId);
            encodedKeyId = encodeText(keyId);
            int outputLength =
                    VERSION_2_MAGIC.length
                            + Integer.BYTES * 4
                            + encodedUsername.length
                            + encodedVaultId.length
                            + encodedEnrollmentId.length
                            + Long.BYTES
                            + encodedKeyId.length;
            output = new byte[outputLength];
            ByteBuffer.wrap(output)
                    .put(VERSION_2_MAGIC)
                    .putInt(encodedUsername.length)
                    .put(encodedUsername)
                    .putInt(encodedVaultId.length)
                    .put(encodedVaultId)
                    .putInt(encodedEnrollmentId.length)
                    .put(encodedEnrollmentId)
                    .putLong(generation)
                    .putInt(encodedKeyId.length)
                    .put(encodedKeyId);
            completed = true;
            return output;
        } finally {
            wipe(encodedUsername);
            wipe(encodedVaultId);
            wipe(encodedEnrollmentId);
            wipe(encodedKeyId);
            if (!completed) {
                wipe(output);
            }
        }
    }

    static byte @NonNull [] legacyVersion1(
            @NonNull String username,
            @NonNull String vaultId,
            @NonNull String enrollmentId,
            long generation,
            @NonNull String keyId) {
        requirePositiveGeneration(generation);
        byte @Nullable [] encodedUsername = null;
        byte @Nullable [] encodedVaultId = null;
        byte @Nullable [] encodedEnrollmentId = null;
        byte @Nullable [] encodedGeneration = null;
        byte @Nullable [] encodedKeyId = null;
        byte @Nullable [] output = null;
        boolean completed = false;
        try {
            encodedUsername = encodeText(username);
            encodedVaultId = encodeText(vaultId);
            encodedEnrollmentId = encodeText(enrollmentId);
            encodedGeneration = Long.toString(generation).getBytes(StandardCharsets.US_ASCII);
            encodedKeyId = encodeText(keyId);
            int outputLength =
                    LEGACY_PREFIX.length
                            + encodedUsername.length
                            + LEGACY_VAULT.length
                            + encodedVaultId.length
                            + LEGACY_ENROLLMENT.length
                            + encodedEnrollmentId.length
                            + LEGACY_GENERATION.length
                            + encodedGeneration.length
                            + LEGACY_KEY.length
                            + encodedKeyId.length;
            output = new byte[outputLength];
            ByteBuffer.wrap(output)
                    .put(LEGACY_PREFIX)
                    .put(encodedUsername)
                    .put(LEGACY_VAULT)
                    .put(encodedVaultId)
                    .put(LEGACY_ENROLLMENT)
                    .put(encodedEnrollmentId)
                    .put(LEGACY_GENERATION)
                    .put(encodedGeneration)
                    .put(LEGACY_KEY)
                    .put(encodedKeyId);
            completed = true;
            return output;
        } finally {
            wipe(encodedUsername);
            wipe(encodedVaultId);
            wipe(encodedEnrollmentId);
            wipe(encodedGeneration);
            wipe(encodedKeyId);
            if (!completed) {
                wipe(output);
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
            wipe(workspace);
        }
    }

    private static void requirePositiveGeneration(long generation) {
        if (generation <= 0) {
            throw new IllegalArgumentException("Recovery generation must be positive");
        }
    }

    private static void wipe(byte @Nullable [] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }
}
