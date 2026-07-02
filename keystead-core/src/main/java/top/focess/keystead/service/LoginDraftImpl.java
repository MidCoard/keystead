package top.focess.keystead.service;

import top.focess.keystead.memory.SecretBuffer;

import java.util.*;

final class LoginDraftImpl implements LoginDraft, AutoCloseable {

    private String title;
    private final Set<String> tags = new LinkedHashSet<>();
    private byte[] username;
    private byte[] password;
    private String url;
    private byte[] notes;
    private boolean closed;

    @Override
    public LoginDraft title(String title) {
        requireOpen();
        this.title = Objects.requireNonNull(title, "title");
        return this;
    }

    @Override
    public LoginDraft tag(String tag) {
        requireOpen();
        if (tag != null && !tag.isBlank()) {
            tags.add(tag);
        }
        return this;
    }

    @Override
    public LoginDraft username(SecretBuffer username) {
        requireOpen();
        replaceUsername(copySecret(username));
        return this;
    }

    @Override
    public LoginDraft password(SecretBuffer password) {
        requireOpen();
        replacePassword(copySecret(password));
        return this;
    }

    @Override
    public LoginDraft url(String url) {
        requireOpen();
        this.url = url;
        return this;
    }

    @Override
    public LoginDraft notes(SecretBuffer notes) {
        requireOpen();
        replaceNotes(copySecret(notes));
        return this;
    }

    String title() {
        return title;
    }

    Set<String> tags() {
        return Set.copyOf(tags);
    }

    String url() {
        return url;
    }

    byte[] usernameBytes() {
        return copyOrNull(username);
    }

    byte[] passwordBytes() {
        return copyOrNull(password);
    }

    byte[] notesBytes() {
        return copyOrNull(notes);
    }

    void validate() {
        requireOpen();
        if (title == null || title.isBlank()) {
            throw new ValidationException("Login title is required");
        }
        if (password == null || password.length == 0) {
            throw new ValidationException("Login password is required");
        }
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

    private byte[] copySecret(SecretBuffer buffer) {
        Objects.requireNonNull(buffer, "buffer");
        byte[][] output = new byte[1][];
        buffer.copyBytes(bytes -> output[0] = bytes.clone());
        return output[0];
    }

    private void replaceUsername(byte[] value) {
        wipe(username);
        username = value;
    }

    private void replacePassword(byte[] value) {
        wipe(password);
        password = value;
    }

    private void replaceNotes(byte[] value) {
        wipe(notes);
        notes = value;
    }

    private byte[] copyOrNull(byte[] value) {
        return value == null ? null : value.clone();
    }

    private void requireOpen() {
        if (closed) {
            throw new IllegalStateException("Login draft is closed");
        }
    }

    private void wipe(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }
}
