package top.focess.keystead.memory;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CoderResult;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.Consumer;
import org.jspecify.annotations.NonNull;

/**
 * An owned, wipeable container for secret bytes.
 *
 * <p>{@code SecretBuffer} is the canonical way to hand short-lived secret material to the vault
 * API. It copies caller bytes on construction and wipes them on {@link #close()}; {@link
 * #toString()} always returns a redacted marker. After close, every accessor throws {@link
 * SecretDestroyedException}.
 *
 * <p>The JVM cannot guarantee that every transient copy (encoder buffers, GC relocation) is erased,
 * so this type minimizes ownership and lifetime rather than promising perfect erasure.
 */
public final class SecretBuffer implements AutoCloseable {

    private final SecretMemory memory;

    private SecretBuffer(@NonNull SecretMemory memory) {
        this.memory = Objects.requireNonNull(memory, "memory");
    }

    /** Creates a buffer that owns a defensive copy of the given UTF-8 bytes. */
    public static @NonNull SecretBuffer fromUtf8(byte @NonNull [] bytes) {
        return fromUtf8(bytes, SecretMemoryProvider.systemDefault());
    }

    public static @NonNull SecretBuffer fromUtf8(
            byte @NonNull [] bytes, @NonNull SecretMemoryProvider memoryProvider) {
        Objects.requireNonNull(bytes, "bytes");
        Objects.requireNonNull(memoryProvider, "memoryProvider");
        return new SecretBuffer(
                Objects.requireNonNull(memoryProvider.protect(bytes), "protected memory"));
    }

    /**
     * Encodes the given characters as UTF-8 and owns the result. The input character array is
     * copied and wiped; the caller remains responsible for the original array.
     */
    public static @NonNull SecretBuffer fromChars(char @NonNull [] chars) {
        return fromChars(chars, SecretMemoryProvider.systemDefault());
    }

    public static @NonNull SecretBuffer fromChars(
            char @NonNull [] chars, @NonNull SecretMemoryProvider memoryProvider) {
        Objects.requireNonNull(chars, "chars");
        Objects.requireNonNull(memoryProvider, "memoryProvider");
        char[] copy = Arrays.copyOf(chars, chars.length);
        byte[] work = null;
        byte[] output = null;
        try {
            CharsetEncoder encoder = StandardCharsets.UTF_8.newEncoder();
            work = new byte[workCapacity(copy.length, encoder.maxBytesPerChar())];
            ByteBuffer target = ByteBuffer.wrap(work);
            requireComplete(encoder.encode(CharBuffer.wrap(copy), target, true), "encoder");
            requireComplete(encoder.flush(target), "encoder");
            output = Arrays.copyOf(work, target.position());
            return new SecretBuffer(
                    Objects.requireNonNull(memoryProvider.protect(output), "protected memory"));
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("Secret characters could not be encoded", e);
        } finally {
            if (output != null) {
                Arrays.fill(output, (byte) 0);
            }
            if (work != null) {
                Arrays.fill(work, (byte) 0);
            }
            Arrays.fill(copy, '\0');
        }
    }

    /** @return the number of secret bytes. */
    public int length() {
        return memory.length();
    }

    /** @return whether this buffer has been closed and its bytes wiped. */
    public boolean isClosed() {
        return memory.isClosed();
    }

    /**
     * Copies the secret bytes and hands them to the callback; the copy is wiped when the callback
     * returns, so callers must not retain it.
     */
    public void copyBytes(@NonNull Consumer<byte[]> consumer) {
        memory.copyBytes(Objects.requireNonNull(consumer, "consumer"));
    }

    /**
     * Decodes the secret to characters and hands them to the callback; the copy is wiped when the
     * callback returns, so callers must not retain it and should avoid copying it into a {@link
     * String}.
     */
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

    /** Wipes the secret bytes. Closing an already-closed buffer is a no-op. */
    @Override
    public void close() {
        memory.close();
    }

    @Override
    public @NonNull String toString() {
        return "[REDACTED SECRET]";
    }

    private static char @NonNull [] decodeToChars(byte @NonNull [] bytes) {
        char[] work = null;
        try {
            CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder();
            work = new char[workCapacity(bytes.length, decoder.maxCharsPerByte())];
            CharBuffer target = CharBuffer.wrap(work);
            requireComplete(decoder.decode(ByteBuffer.wrap(bytes), target, true), "decoder");
            requireComplete(decoder.flush(target), "decoder");
            return Arrays.copyOf(work, target.position());
        } catch (CharacterCodingException e) {
            throw new IllegalStateException("Secret bytes could not be decoded", e);
        } finally {
            if (work != null) {
                Arrays.fill(work, '\0');
            }
        }
    }

    private static int workCapacity(int inputLength, float maximumExpansion) {
        try {
            return Math.multiplyExact(inputLength, (int) Math.ceil(maximumExpansion));
        } catch (ArithmeticException error) {
            throw new IllegalArgumentException("Secret value is too large", error);
        }
    }

    private static void requireComplete(@NonNull CoderResult result, @NonNull String operation)
            throws CharacterCodingException {
        if (result.isError()) {
            result.throwException();
        }
        if (result.isOverflow()) {
            throw new IllegalStateException("UTF-8 " + operation + " exceeded its work buffer");
        }
    }
}
