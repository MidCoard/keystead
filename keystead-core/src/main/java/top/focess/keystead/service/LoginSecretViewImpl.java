package top.focess.keystead.service;

import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.memory.SecretDestroyedException;
import top.focess.keystead.model.SecretMetadata;

import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;

final class LoginSecretViewImpl implements LoginSecretView, AutoCloseable {

    private final SecretMetadata metadata;
    private final String url;
    private final byte[] username;
    private final byte[] password;
    private final byte[] notes;
    private boolean closed;

    LoginSecretViewImpl(SecretMetadata metadata, String url, byte[] username, byte[] password, byte[] notes) {
        this.metadata = Objects.requireNonNull(metadata, "metadata");
        this.url = url;
        this.username = copyOrNull(username);
        this.password = copyOrNull(password);
        this.notes = copyOrNull(notes);
    }

    @Override
    public SecretMetadata metadata() {
        requireOpen();
        return metadata;
    }

    @Override
    public Optional<String> url() {
        requireOpen();
        return Optional.ofNullable(url);
    }

    @Override
    public void withUsername(Consumer<char[]> consumer) {
        withSecret(username, consumer);
    }

    @Override
    public void withPassword(Consumer<char[]> consumer) {
        withSecret(password, consumer);
    }

    @Override
    public void withNotes(Consumer<char[]> consumer) {
        withSecret(notes, consumer);
    }

    @Override
    public void close() {
        if (!closed) {
            wipe(username);
            wipe(password);
            wipe(notes);
            closed = true;
        }
    }

    private void withSecret(byte[] value, Consumer<char[]> consumer) {
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

    private byte[] copyOrNull(byte[] value) {
        return value == null ? null : value.clone();
    }

    private void wipe(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }
}
