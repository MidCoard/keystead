package top.focess.keystead.service;

import java.nio.ByteBuffer;
import java.util.Arrays;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.model.SecretMetadata;

final class SecureNotePayloadCodec {

    private static final int VERSION = 1;

    private SecureNotePayloadCodec() {}

    static byte @NonNull [] encode(@NonNull SecureNoteDraftImpl draft) {
        byte @Nullable [] body = draft.bodyBytes();
        try {
            int size = Integer.BYTES + Integer.BYTES + (body == null ? 0 : body.length);
            ByteBuffer buffer = ByteBuffer.allocate(size);
            buffer.putInt(VERSION);
            putBytes(buffer, body);
            return buffer.array();
        } finally {
            wipe(body);
        }
    }

    static @NonNull SecureNoteViewImpl decode(
            @NonNull SecretMetadata metadata, byte @NonNull [] payload) {
        ByteBuffer buffer = ByteBuffer.wrap(payload);
        int version = buffer.getInt();
        if (version != VERSION) {
            throw new ValidationException("Unsupported secure note payload version");
        }
        byte @Nullable [] body = readBytes(buffer);
        try {
            return new SecureNoteViewImpl(metadata, body);
        } finally {
            wipe(body);
        }
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
        int length = buffer.getInt();
        if (length < 0) {
            return null;
        }
        byte[] value = new byte[length];
        buffer.get(value);
        return value;
    }

    private static void wipe(byte @Nullable [] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }
}
