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

    private final SecretMemory memory;

    private SecretBuffer(@NonNull SecretMemory memory) {
        this.memory = Objects.requireNonNull(memory, "memory");
    }

    public static @NonNull SecretBuffer fromUtf8(byte @NonNull [] bytes) {
        return fromUtf8(bytes, SecretMemoryProvider.heap());
    }

    public static @NonNull SecretBuffer fromUtf8(
            byte @NonNull [] bytes, @NonNull SecretMemoryProvider memoryProvider) {
        Objects.requireNonNull(bytes, "bytes");
        Objects.requireNonNull(memoryProvider, "memoryProvider");
        return new SecretBuffer(
                Objects.requireNonNull(memoryProvider.protect(bytes), "protected memory"));
    }

    public static @NonNull SecretBuffer fromChars(char @NonNull [] chars) {
        return fromChars(chars, SecretMemoryProvider.heap());
    }

    public static @NonNull SecretBuffer fromChars(
            char @NonNull [] chars, @NonNull SecretMemoryProvider memoryProvider) {
        Objects.requireNonNull(chars, "chars");
        Objects.requireNonNull(memoryProvider, "memoryProvider");
        char[] copy = Arrays.copyOf(chars, chars.length);
        try {
            ByteBuffer encoded = StandardCharsets.UTF_8.newEncoder().encode(CharBuffer.wrap(copy));
            byte[] output = new byte[encoded.remaining()];
            encoded.get(output);
            wipeByteBuffer(encoded);
            try {
                return new SecretBuffer(
                        Objects.requireNonNull(memoryProvider.protect(output), "protected memory"));
            } finally {
                Arrays.fill(output, (byte) 0);
            }
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("Secret characters could not be encoded", e);
        } finally {
            Arrays.fill(copy, '\0');
        }
    }

    public int length() {
        return memory.length();
    }

    public boolean isClosed() {
        return memory.isClosed();
    }

    public void copyBytes(@NonNull Consumer<byte[]> consumer) {
        memory.copyBytes(Objects.requireNonNull(consumer, "consumer"));
    }

    public void copyChars(@NonNull Consumer<char[]> consumer) {
        Objects.requireNonNull(consumer, "consumer");
        memory.copyBytes(
                bytes -> {
                    char[] copy = decodeToChars(bytes);
                    try {
                        consumer.accept(copy);
                    } finally {
                        Arrays.fill(copy, '\0');
                    }
                });
    }

    @Override
    public void close() {
        memory.close();
    }

    @Override
    public @NonNull String toString() {
        return "[REDACTED SECRET]";
    }

    private static char @NonNull [] decodeToChars(byte @NonNull [] bytes) {
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
