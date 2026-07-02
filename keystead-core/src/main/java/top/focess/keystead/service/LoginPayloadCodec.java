package top.focess.keystead.service;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.model.SecretMetadata;

final class LoginPayloadCodec {

    private static final int VERSION = 1;

    private LoginPayloadCodec() {}

    static byte @NonNull [] encode(@NonNull LoginDraftImpl draft) {
        byte @Nullable [] url = bytesOrNull(draft.url());
        byte @Nullable [] username = draft.usernameBytes();
        byte @Nullable [] password = draft.passwordBytes();
        byte @Nullable [] notes = draft.notesBytes();
        try {
            int size =
                    Integer.BYTES
                            + sizeOf(url)
                            + sizeOf(username)
                            + sizeOf(password)
                            + sizeOf(notes);
            ByteBuffer buffer = ByteBuffer.allocate(size);
            buffer.putInt(VERSION);
            putBytes(buffer, url);
            putBytes(buffer, username);
            putBytes(buffer, password);
            putBytes(buffer, notes);
            return buffer.array();
        } finally {
            wipe(url);
            wipe(username);
            wipe(password);
            wipe(notes);
        }
    }

    static @NonNull LoginSecretViewImpl decode(
            @NonNull SecretMetadata metadata, byte @NonNull [] payload) {
        ByteBuffer buffer = ByteBuffer.wrap(payload);
        int version = readInt(buffer);
        if (version != VERSION) {
            throw new ValidationException("Unsupported login payload version");
        }
        byte @Nullable [] urlBytes = readBytes(buffer);
        byte @Nullable [] username = readBytes(buffer);
        byte @Nullable [] password = readBytes(buffer);
        byte @Nullable [] notes = readBytes(buffer);
        try {
            String url = urlBytes == null ? null : new String(urlBytes, StandardCharsets.UTF_8);
            if (buffer.hasRemaining()) {
                throw new ValidationException("Login payload contains trailing data");
            }
            return new LoginSecretViewImpl(metadata, url, username, password, notes);
        } finally {
            wipe(urlBytes);
            wipe(username);
            wipe(password);
            wipe(notes);
        }
    }

    private static byte @Nullable [] bytesOrNull(@Nullable String value) {
        return value == null ? null : value.getBytes(StandardCharsets.UTF_8);
    }

    private static int sizeOf(byte @Nullable [] value) {
        return Integer.BYTES + (value == null ? 0 : value.length);
    }

    private static void putBytes(@NonNull ByteBuffer buffer, byte @Nullable [] value) {
        if (value == null) {
            buffer.putInt(-1);
            return;
        }
        buffer.putInt(value.length);
        buffer.put(value);
    }

    private static byte @Nullable [] readBytes(@NonNull ByteBuffer buffer) {
        int length = readInt(buffer);
        if (length == -1) {
            return null;
        }
        if (length < -1) {
            throw new ValidationException("Login payload contains an invalid field length");
        }
        if (length > buffer.remaining()) {
            throw new ValidationException("Login payload field is truncated");
        }
        byte[] value = new byte[length];
        buffer.get(value);
        return value;
    }

    private static int readInt(@NonNull ByteBuffer buffer) {
        if (buffer.remaining() < Integer.BYTES) {
            throw new ValidationException("Login payload is truncated");
        }
        return buffer.getInt();
    }

    private static void wipe(byte @Nullable [] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }
}
