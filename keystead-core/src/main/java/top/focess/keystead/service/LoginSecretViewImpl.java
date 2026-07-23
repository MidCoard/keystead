package top.focess.keystead.service;

import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.memory.SecretDestroyedException;
import top.focess.keystead.memory.Wipe;
import top.focess.keystead.model.SecretMetadata;

final class LoginSecretViewImpl implements LoginSecretView, AutoCloseable {

    private final SecretMetadata metadata;
    private final @Nullable String url;
    private final byte @Nullable [] username;
    private final byte @Nullable [] password;
    private final byte @Nullable [] notes;
    private boolean closed;

    LoginSecretViewImpl(
            @NonNull SecretMetadata metadata,
            @Nullable String url,
            byte @Nullable [] username,
            byte @Nullable [] password,
            byte @Nullable [] notes) {
        this.metadata = Objects.requireNonNull(metadata, "metadata");
        this.url = url;
        this.username = copyOrNull(username);
        this.password = copyOrNull(password);
        this.notes = copyOrNull(notes);
    }

    @Override
    public @NonNull SecretMetadata metadata() {
        requireOpen();
        return metadata;
    }

    @Override
    public @NonNull Optional<String> url() {
        requireOpen();
        return Optional.ofNullable(url);
    }

    @Override
    public void withUsername(@NonNull Consumer<char[]> consumer) {
        withSecret(username, consumer);
    }

    @Override
    public void withPassword(@NonNull Consumer<char[]> consumer) {
        withSecret(password, consumer);
    }

    @Override
    public void withNotes(@NonNull Consumer<char[]> consumer) {
        withSecret(notes, consumer);
    }

    @Override
    public void close() {
        if (!closed) {
            Wipe.wipe(username);
            Wipe.wipe(password);
            Wipe.wipe(notes);
            closed = true;
        }
    }

    private void withSecret(byte @Nullable [] value, @NonNull Consumer<char[]> consumer) {
        Objects.requireNonNull(consumer, "consumer");
        requireOpen();
        byte[] source = value == null ? new byte[0] : value;
        try (SecretBuffer buffer = SecretBuffer.fromUtf8(source)) {
            buffer.copyChars(consumer);
        }
    }

    private void requireOpen() {
        if (closed) {
            throw new SecretDestroyedException();
        }
    }

    private byte @Nullable [] copyOrNull(byte @Nullable [] value) {
        return value == null ? null : value.clone();
    }
}
