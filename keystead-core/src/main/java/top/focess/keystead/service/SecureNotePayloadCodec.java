package top.focess.keystead.service;

import java.nio.ByteBuffer;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.memory.Wipe;
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
            Wipe.wipe(body);
        }
    }

    static @NonNull SecureNoteViewImpl decode(
            @NonNull SecretMetadata metadata, byte @NonNull [] payload) {
        ByteBuffer buffer = ByteBuffer.wrap(payload);
        int version = readInt(buffer);
        if (version != VERSION) {
            throw new ValidationException("Unsupported secure note payload version");
        }
        byte @Nullable [] body = readBytes(buffer);
        try {
            if (buffer.hasRemaining()) {
                throw new ValidationException("Secure note payload contains trailing data");
            }
            return new SecureNoteViewImpl(metadata, body);
        } finally {
            Wipe.wipe(body);
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
        int length = readInt(buffer);
        if (length == -1) {
            return null;
        }
        if (length < -1) {
            throw new ValidationException("Secure note payload contains an invalid field length");
        }
        if (length > buffer.remaining()) {
            throw new ValidationException("Secure note payload field is truncated");
        }
        byte[] value = new byte[length];
        buffer.get(value);
        return value;
    }

    private static int readInt(@NonNull ByteBuffer buffer) {
        if (buffer.remaining() < Integer.BYTES) {
            throw new ValidationException("Secure note payload is truncated");
        }
        return buffer.getInt();
    }
}
