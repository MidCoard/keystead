package top.focess.keystead.service;

import java.util.Objects;
import java.util.function.Consumer;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.memory.SecretDestroyedException;
import top.focess.keystead.memory.Wipe;
import top.focess.keystead.model.SecretMetadata;

final class SecureNoteViewImpl implements SecureNoteView, AutoCloseable {

    private final SecretMetadata metadata;
    private final byte @Nullable [] body;
    private boolean closed;

    SecureNoteViewImpl(@NonNull SecretMetadata metadata, byte @Nullable [] body) {
        this.metadata = Objects.requireNonNull(metadata, "metadata");
        this.body = body == null ? null : body.clone();
    }

    @Override
    public @NonNull SecretMetadata metadata() {
        requireOpen();
        return metadata;
    }

    @Override
    public void withBody(@NonNull Consumer<char[]> consumer) {
        Objects.requireNonNull(consumer, "consumer");
        requireOpen();
        byte[] source = body == null ? new byte[0] : body;
        try (SecretBuffer buffer = SecretBuffer.fromUtf8(source)) {
            buffer.copyChars(consumer);
        }
    }

    @Override
    public void close() {
        if (!closed) {
            Wipe.wipe(body);
            closed = true;
        }
    }

    private void requireOpen() {
        if (closed) {
            throw new SecretDestroyedException();
        }
    }
}
