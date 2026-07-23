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

final class StructuredSecretDraftImpl implements StructuredSecretDraft, AutoCloseable {

    private @Nullable String title;
    private @NonNull SecretClassification classification = SecretClassification.none();
    private final Set<String> tags = new LinkedHashSet<>();
    private final Map<String, String> attributes = new LinkedHashMap<>();
    private final Map<String, byte[]> fields = new LinkedHashMap<>();
    private boolean closed;

    @Override
    public @NonNull StructuredSecretDraft title(@NonNull String title) {
        requireOpen();
        this.title = Objects.requireNonNull(title, "title");
        return this;
    }

    @Override
    public @NonNull StructuredSecretDraft tag(@Nullable String tag) {
        requireOpen();
        if (tag != null && !tag.isBlank()) {
            tags.add(tag);
        }
        return this;
    }

    @Override
    public @NonNull StructuredSecretDraft classification(
            @NonNull SecretClassification classification) {
        requireOpen();
        this.classification = Objects.requireNonNull(classification, "classification");
        return this;
    }

    @Override
    public @NonNull StructuredSecretDraft attribute(@NonNull String key, @NonNull String value) {
        requireOpen();
        if (!Objects.requireNonNull(key, "key").isBlank()
                && !Objects.requireNonNull(value, "value").isBlank()) {
            attributes.put(key, value);
        }
        return this;
    }

    @Override
    public @NonNull StructuredSecretDraft field(@NonNull String name, @NonNull SecretBuffer value) {
        requireOpen();
        String normalized = Objects.requireNonNull(name, "name").strip();
        if (!normalized.isBlank()) {
            replaceField(normalized, copySecret(value));
        }
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

    @NonNull Map<String, byte[]> fields() {
        Map<String, byte[]> copy = new LinkedHashMap<>();
        fields.forEach((key, value) -> copy.put(key, value.clone()));
        return copy;
    }

    void validate() {
        requireOpen();
        if (title == null || title.isBlank()) {
            throw new ValidationException("Structured secret title is required");
        }
        if (fields.isEmpty()) {
            throw new ValidationException("Structured secret needs at least one field");
        }
    }

    @Override
    public void close() {
        if (!closed) {
            fields.values().forEach(Wipe::wipe);
            fields.clear();
            closed = true;
        }
    }

    private byte @NonNull [] copySecret(@NonNull SecretBuffer buffer) {
        Objects.requireNonNull(buffer, "buffer");
        byte[][] output = new byte[1][];
        buffer.copyBytes(bytes -> output[0] = bytes.clone());
        return output[0];
    }

    private void replaceField(@NonNull String name, byte @NonNull [] value) {
        byte @Nullable [] previous = fields.put(name, value);
        Wipe.wipe(previous);
    }

    private void requireOpen() {
        if (closed) {
            throw new IllegalStateException("Structured secret draft is closed");
        }
    }
}
