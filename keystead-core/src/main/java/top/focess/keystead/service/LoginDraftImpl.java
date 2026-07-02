package top.focess.keystead.service;

import java.util.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.model.SecretClassification;

final class LoginDraftImpl implements LoginDraft, AutoCloseable {

    private @Nullable String title;
    private @NonNull SecretClassification classification = SecretClassification.none();
    private final Set<String> tags = new LinkedHashSet<>();
    private byte @Nullable [] username;
    private byte @Nullable [] password;
    private @Nullable String url;
    private byte @Nullable [] notes;
    private boolean closed;

    @Override
    public @NonNull LoginDraft title(@NonNull String title) {
        requireOpen();
        this.title = Objects.requireNonNull(title, "title");
        return this;
    }

    @Override
    public @NonNull LoginDraft tag(@Nullable String tag) {
        requireOpen();
        if (tag != null && !tag.isBlank()) {
            tags.add(tag);
        }
        return this;
    }

    @Override
    public @NonNull LoginDraft classification(@NonNull SecretClassification classification) {
        requireOpen();
        this.classification = Objects.requireNonNull(classification, "classification");
        return this;
    }

    @Override
    public @NonNull LoginDraft username(@NonNull SecretBuffer username) {
        requireOpen();
        replaceUsername(copySecret(username));
        return this;
    }

    @Override
    public @NonNull LoginDraft password(@NonNull SecretBuffer password) {
        requireOpen();
        replacePassword(copySecret(password));
        return this;
    }

    @Override
    public @NonNull LoginDraft url(@Nullable String url) {
        requireOpen();
        this.url = url;
        return this;
    }

    @Override
    public @NonNull LoginDraft notes(@NonNull SecretBuffer notes) {
        requireOpen();
        replaceNotes(copySecret(notes));
        return this;
    }

    @Nullable String title() {
        return title;
    }

    @NonNull Set<String> tags() {
        return Set.copyOf(tags);
    }

    @NonNull SecretClassification classification() {
        return classification;
    }

    @Nullable String url() {
        return url;
    }

    byte @Nullable [] usernameBytes() {
        return copyOrNull(username);
    }

    byte @Nullable [] passwordBytes() {
        return copyOrNull(password);
    }

    byte @Nullable [] notesBytes() {
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

    private byte @NonNull [] copySecret(@NonNull SecretBuffer buffer) {
        Objects.requireNonNull(buffer, "buffer");
        byte[][] output = new byte[1][];
        buffer.copyBytes(bytes -> output[0] = bytes.clone());
        return output[0];
    }

    private void replaceUsername(byte @NonNull [] value) {
        wipe(username);
        username = value;
    }

    private void replacePassword(byte @NonNull [] value) {
        wipe(password);
        password = value;
    }

    private void replaceNotes(byte @NonNull [] value) {
        wipe(notes);
        notes = value;
    }

    private byte @Nullable [] copyOrNull(byte @Nullable [] value) {
        return value == null ? null : value.clone();
    }

    private void requireOpen() {
        if (closed) {
            throw new IllegalStateException("Login draft is closed");
        }
    }

    private void wipe(byte @Nullable [] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }
}
