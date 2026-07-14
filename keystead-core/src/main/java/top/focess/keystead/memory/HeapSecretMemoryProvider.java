package top.focess.keystead.memory;

import java.util.Arrays;
import java.util.Objects;
import java.util.function.Consumer;
import org.jspecify.annotations.NonNull;

public final class HeapSecretMemoryProvider implements SecretMemoryProvider {

    private static final HeapSecretMemoryProvider INSTANCE = new HeapSecretMemoryProvider();

    private HeapSecretMemoryProvider() {}

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
                Arrays.fill(copy, (byte) 0);
            }
        }

        @Override
        public synchronized void close() {
            if (!closed) {
                Arrays.fill(bytes, (byte) 0);
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
