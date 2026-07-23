package top.focess.keystead.service;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.Wipe;
import top.focess.keystead.model.SecretMetadata;

final class StructuredSecretPayloadCodec {

    private static final int VERSION = 1;

    private StructuredSecretPayloadCodec() {}

    static byte @NonNull [] encode(@NonNull StructuredSecretDraftImpl draft) {
        Map<String, byte[]> fields = draft.fields();
        try {
            int size = Integer.BYTES + Integer.BYTES;
            for (Map.Entry<String, byte[]> entry : fields.entrySet()) {
                size += sizeOf(entry.getKey().getBytes(StandardCharsets.UTF_8));
                size += sizeOf(entry.getValue());
            }
            ByteBuffer buffer = ByteBuffer.allocate(size);
            buffer.putInt(VERSION);
            buffer.putInt(fields.size());
            for (Map.Entry<String, byte[]> entry : fields.entrySet()) {
                putBytes(buffer, entry.getKey().getBytes(StandardCharsets.UTF_8));
                putBytes(buffer, entry.getValue());
            }
            return buffer.array();
        } finally {
            fields.values().forEach(Wipe::wipe);
        }
    }

    static @NonNull StructuredSecretViewImpl decode(
            @NonNull SecretMetadata metadata, byte @NonNull [] payload) {
        ByteBuffer buffer = ByteBuffer.wrap(payload);
        int version = readInt(buffer);
        if (version != VERSION) {
            throw new ValidationException("Unsupported structured secret payload version");
        }
        int fieldCount = readInt(buffer);
        if (fieldCount < 0) {
            throw new ValidationException("Structured secret payload contains invalid field count");
        }

        Map<String, byte[]> fields = new LinkedHashMap<>();
        try {
            for (int index = 0; index < fieldCount; index++) {
                byte[] nameBytes = readBytes(buffer);
                byte[] value = readBytes(buffer);
                String name = new String(nameBytes, StandardCharsets.UTF_8);
                Wipe.wipe(nameBytes);
                if (name.isBlank()) {
                    Wipe.wipe(value);
                    throw new ValidationException(
                            "Structured secret payload contains blank field name");
                }
                byte[] previous = fields.put(name, value);
                if (previous != null) {
                    Wipe.wipe(previous);
                    throw new ValidationException(
                            "Structured secret payload contains duplicate field name");
                }
            }
            if (buffer.hasRemaining()) {
                throw new ValidationException("Structured secret payload contains trailing data");
            }
            return new StructuredSecretViewImpl(metadata, fields);
        } finally {
            fields.values().forEach(Wipe::wipe);
        }
    }

    private static int sizeOf(byte @NonNull [] value) {
        return Integer.BYTES + value.length;
    }

    private static void putBytes(@NonNull ByteBuffer buffer, byte @NonNull [] value) {
        buffer.putInt(value.length);
        buffer.put(value);
    }

    private static byte @NonNull [] readBytes(@NonNull ByteBuffer buffer) {
        int length = readInt(buffer);
        if (length < 0) {
            throw new ValidationException(
                    "Structured secret payload contains invalid field length");
        }
        if (length > buffer.remaining()) {
            throw new ValidationException("Structured secret payload field is truncated");
        }
        byte[] value = new byte[length];
        buffer.get(value);
        return value;
    }

    private static int readInt(@NonNull ByteBuffer buffer) {
        if (buffer.remaining() < Integer.BYTES) {
            throw new ValidationException("Structured secret payload is truncated");
        }
        return buffer.getInt();
    }
}
