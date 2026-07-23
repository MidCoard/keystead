package top.focess.keystead.memory;

import java.util.Arrays;
import java.util.Objects;
import java.util.function.Consumer;
import org.jspecify.annotations.NonNull;

/**
 * Heap-backed {@link SecretMemoryProvider} that wipes secret bytes on close. Used as the explicit
 * fallback when native locked memory is not required; it provides no page-locking or dump-exclusion
 * guarantees.
 */
public final class HeapSecretMemoryProvider implements SecretMemoryProvider {

    private static final HeapSecretMemoryProvider INSTANCE = new HeapSecretMemoryProvider();

    private HeapSecretMemoryProvider() {}

    /**
     * Returns the process-wide singleton.
     *
     * @return the process-wide singleton
     */
    public static @NonNull HeapSecretMemoryProvider instance() {
        return INSTANCE;
    }

    @Override
    public @NonNull SecretMemory protect(byte @NonNull [] value) {
        Objects.requireNonNull(value, "value");
        return new HeapSecretMemory(Arrays.copyOf(value, value.length));
    }

    private static final class HeapSecretMemory implements SecretMemory {

        private final byte[] bytes;
        private boolean closed;

        private HeapSecretMemory(byte @NonNull [] bytes) {
            this.bytes = bytes;
        }

        @Override
        public synchronized int length() {
            requireOpen();
            return bytes.length;
        }

        @Override
        public synchronized boolean isClosed() {
            return closed;
        }

        @Override
        public synchronized void copyBytes(@NonNull Consumer<byte[]> consumer) {
            Objects.requireNonNull(consumer, "consumer");
            requireOpen();
            byte[] copy = Arrays.copyOf(bytes, bytes.length);
            try {
                consumer.accept(copy);
            } finally {
                Wipe.wipe(copy);
            }
        }

        @Override
        public synchronized void close() {
            if (!closed) {
                Wipe.wipe(bytes);
                closed = true;
            }
        }

        private void requireOpen() {
            if (closed) {
                throw new SecretDestroyedException();
            }
        }
    }
}
