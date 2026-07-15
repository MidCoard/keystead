package top.focess.keystead.testing;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.SecretMemory;
import top.focess.keystead.memory.SecretMemoryProvider;

public final class RecordingSecretMemoryProvider implements SecretMemoryProvider {

    private final List<TrackingSecretMemory> owners = new ArrayList<>();

    @Override
    public synchronized @NonNull SecretMemory protect(byte @NonNull [] value) {
        TrackingSecretMemory owner =
                new TrackingSecretMemory(SecretMemoryProvider.heap().protect(value));
        owners.add(owner);
        return owner;
    }

    public synchronized int ownerCount() {
        return owners.size();
    }

    public synchronized @NonNull TrackingSecretMemory owner(int index) {
        return owners.get(index);
    }

    public synchronized @NonNull TrackingSecretMemory lastOwner() {
        return owners.get(owners.size() - 1);
    }

    public static final class TrackingSecretMemory implements SecretMemory {

        private final SecretMemory delegate;

        private TrackingSecretMemory(@NonNull SecretMemory delegate) {
            this.delegate = delegate;
        }

        @Override
        public int length() {
            return delegate.length();
        }

        @Override
        public boolean isClosed() {
            return delegate.isClosed();
        }

        @Override
        public void copyBytes(@NonNull Consumer<byte[]> consumer) {
            delegate.copyBytes(consumer);
        }

        @Override
        public void close() {
            delegate.close();
        }
    }
}
