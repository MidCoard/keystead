package top.focess.keystead.service;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.memory.Wipe;
import top.focess.keystead.model.SecretClassification;

final class SecureNoteDraftImpl implements SecureNoteDraft, AutoCloseable {

    private @Nullable String title;
    private @NonNull SecretClassification classification = SecretClassification.none();
    private final Set<String> tags = new LinkedHashSet<>();
    private final Map<String, String> attributes = new LinkedHashMap<>();
    private byte @Nullable [] body;
    private boolean closed;

    @Override
    public @NonNull SecureNoteDraft title(@NonNull String title) {
        requireOpen();
        this.title = Objects.requireNonNull(title, "title");
        return this;
    }

    @Override
    public @NonNull SecureNoteDraft tag(@Nullable String tag) {
        requireOpen();
        if (tag != null && !tag.isBlank()) {
            tags.add(tag);
        }
        return this;
    }

    @Override
    public @NonNull SecureNoteDraft classification(@NonNull SecretClassification classification) {
        requireOpen();
        this.classification = Objects.requireNonNull(classification, "classification");
        return this;
    }

    @Override
    public @NonNull SecureNoteDraft attribute(@NonNull String key, @NonNull String value) {
        requireOpen();
        if (!Objects.requireNonNull(key, "key").isBlank()
                && !Objects.requireNonNull(value, "value").isBlank()) {
            attributes.put(key, value);
        }
        return this;
    }

    @Override
    public @NonNull SecureNoteDraft body(@NonNull SecretBuffer body) {
        requireOpen();
        replaceBody(copySecret(body));
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

    @NonNull Map<String, String> attributes() {
        return Map.copyOf(attributes);
    }

    byte @Nullable [] bodyBytes() {
        return body == null ? null : body.clone();
    }

    void validate() {
        requireOpen();
        if (title == null || title.isBlank()) {
            throw new ValidationException("Secure note title is required");
        }
        if (body == null || body.length == 0) {
            throw new ValidationException("Secure note body is required");
        }
    }

    @Override
    public void close() {
        if (!closed) {
            Wipe.wipe(body);
            closed = true;
        }
    }

    private byte @NonNull [] copySecret(@NonNull SecretBuffer buffer) {
        Objects.requireNonNull(buffer, "buffer");
        byte[][] output = new byte[1][];
        buffer.copyBytes(bytes -> output[0] = bytes.clone());
        return output[0];
    }

    private void replaceBody(byte @NonNull [] value) {
        Wipe.wipe(body);
        body = value;
    }

    private void requireOpen() {
        if (closed) {
            throw new IllegalStateException("Secure note draft is closed");
        }
    }
}
