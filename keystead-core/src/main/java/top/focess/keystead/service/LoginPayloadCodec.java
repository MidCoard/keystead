package top.focess.keystead.service;

import top.focess.keystead.model.SecretMetadata;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

final class LoginPayloadCodec {

    private static final int VERSION = 1;

    private LoginPayloadCodec() {
    }

    static byte[] encode(LoginDraftImpl draft) {
        byte[] url = bytesOrNull(draft.url());
        byte[] username = draft.usernameBytes();
        byte[] password = draft.passwordBytes();
        byte[] notes = draft.notesBytes();
        try {
            int size = Integer.BYTES + sizeOf(url) + sizeOf(username) + sizeOf(password) + sizeOf(notes);
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

    static LoginSecretViewImpl decode(SecretMetadata metadata, byte[] payload) {
        ByteBuffer buffer = ByteBuffer.wrap(payload);
        int version = buffer.getInt();
        if (version != VERSION) {
            throw new ValidationException("Unsupported login payload version");
        }
        byte[] urlBytes = readBytes(buffer);
        byte[] username = readBytes(buffer);
        byte[] password = readBytes(buffer);
        byte[] notes = readBytes(buffer);
        try {
            String url = urlBytes == null ? null : new String(urlBytes, StandardCharsets.UTF_8);
            return new LoginSecretViewImpl(metadata, url, username, password, notes);
        } finally {
            wipe(urlBytes);
            wipe(username);
            wipe(password);
            wipe(notes);
        }
    }

    private static byte[] bytesOrNull(String value) {
        return value == null ? null : value.getBytes(StandardCharsets.UTF_8);
    }

    private static int sizeOf(byte[] value) {
        return Integer.BYTES + (value == null ? 0 : value.length);
    }

    private static void putBytes(ByteBuffer buffer, byte[] value) {
        if (value == null) {
            buffer.putInt(-1);
            return;
        }
        buffer.putInt(value.length);
        buffer.put(value);
    }

    private static byte[] readBytes(ByteBuffer buffer) {
        int length = buffer.getInt();
        if (length < 0) {
            return null;
        }
        byte[] value = new byte[length];
        buffer.get(value);
        return value;
    }

    private static void wipe(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }
}
