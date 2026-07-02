package top.focess.keystead.memory;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.Consumer;
import org.jspecify.annotations.NonNull;

public final class SecretBuffer implements AutoCloseable {

    private final byte[] bytes;
    private boolean closed;

    private SecretBuffer(byte @NonNull [] bytes) {
        this.bytes = Objects.requireNonNull(bytes, "bytes");
    }

    public static @NonNull SecretBuffer fromUtf8(byte @NonNull [] bytes) {
        return new SecretBuffer(
                Arrays.copyOf(Objects.requireNonNull(bytes, "bytes"), bytes.length));
    }

    public static @NonNull SecretBuffer fromChars(char @NonNull [] chars) {
        Objects.requireNonNull(chars, "chars");
        char[] copy = Arrays.copyOf(chars, chars.length);
        try {
            ByteBuffer encoded = StandardCharsets.UTF_8.newEncoder().encode(CharBuffer.wrap(copy));
            byte[] output = new byte[encoded.remaining()];
            encoded.get(output);
            wipeByteBuffer(encoded);
            return new SecretBuffer(output);
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("Secret characters could not be encoded", e);
        } finally {
            Arrays.fill(copy, '\0');
        }
    }

    public int length() {
        requireOpen();
        return bytes.length;
    }

    public boolean isClosed() {
        return closed;
    }

    public void copyBytes(@NonNull Consumer<byte[]> consumer) {
        Objects.requireNonNull(consumer, "consumer");
        requireOpen();
        byte[] copy = Arrays.copyOf(bytes, bytes.length);
        try {
            consumer.accept(copy);
        } finally {
            Arrays.fill(copy, (byte) 0);
        }
    }

    public void copyChars(@NonNull Consumer<char[]> consumer) {
        Objects.requireNonNull(consumer, "consumer");
        requireOpen();
        char[] copy = decodeToChars();
        try {
            consumer.accept(copy);
        } finally {
            Arrays.fill(copy, '\0');
        }
    }

    @Override
    public void close() {
        if (!closed) {
            Arrays.fill(bytes, (byte) 0);
            closed = true;
        }
    }

    @Override
    public @NonNull String toString() {
        return "[REDACTED SECRET]";
    }

    private void requireOpen() {
        if (closed) {
            throw new SecretDestroyedException();
        }
    }

    private char @NonNull [] decodeToChars() {
        try {
            CharBuffer decoded = StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes));
            char[] output = new char[decoded.remaining()];
            decoded.get(output);
            wipeCharBuffer(decoded);
            return output;
        } catch (CharacterCodingException e) {
            throw new IllegalStateException("Secret bytes could not be decoded", e);
        }
    }

    private static void wipeByteBuffer(@NonNull ByteBuffer buffer) {
        if (buffer.hasArray()) {
            Arrays.fill(buffer.array(), (byte) 0);
        }
    }

    private static void wipeCharBuffer(@NonNull CharBuffer buffer) {
        if (buffer.hasArray()) {
            Arrays.fill(buffer.array(), '\0');
        }
    }
}
