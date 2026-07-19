package top.focess.keystead.memory;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

/** Byte-array output stream that destroys its backing storage when closed. */
public class WipeableByteArrayOutputStream extends ByteArrayOutputStream {

    /** Creates an empty stream with the default initial capacity. */
    public WipeableByteArrayOutputStream() {}

    /**
     * Copies the written bytes into a new {@link SecretBuffer} held by the given provider.
     *
     * @param memoryProvider the provider used to protect the bytes
     * @return a new secret buffer owning a copy of the written bytes
     */
    public synchronized @NonNull SecretBuffer toSecretBuffer(
            @NonNull SecretMemoryProvider memoryProvider) {
        Objects.requireNonNull(memoryProvider, "memoryProvider");
        byte[] copy = Arrays.copyOf(buf, count);
        try {
            return SecretBuffer.fromUtf8(copy, memoryProvider);
        } finally {
            Arrays.fill(copy, (byte) 0);
        }
    }

    @Override
    public synchronized void close() {
        Arrays.fill(buf, (byte) 0);
        count = 0;
    }
}
