package top.focess.keystead.service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.model.SecretMetadata;
import top.focess.keystead.model.SecretTypeSchema;

final class StructuredSecretViewImpl implements StructuredSecretView, AutoCloseable {

    private final SecretMetadata metadata;
    private final Map<String, byte[]> fields;
    private boolean closed;

    StructuredSecretViewImpl(
            @NonNull SecretMetadata metadata, @NonNull Map<String, byte[]> fields) {
        this.metadata = Objects.requireNonNull(metadata, "metadata");
        this.fields = copyFields(fields);
    }

    @Override
    public @NonNull SecretMetadata metadata() {
        return metadata;
    }

    @Override
    public @NonNull Set<String> fieldNames() {
        requireOpen();
        return Set.copyOf(fields.keySet());
    }

    @Override
    public @NonNull List<String> orderedFieldNames() {
        requireOpen();
        SecretTypeSchema schema = SecretTypeSchema.forType(metadata.type());
        if (schema.allowsCustomFields()) {
            return List.copyOf(fields.keySet());
        }
        List<String> ordered = new ArrayList<>();
        for (String fieldName : schema.fieldNames()) {
            if (fields.containsKey(fieldName)) {
                ordered.add(fieldName);
            }
        }
        return List.copyOf(ordered);
    }

    @Override
    public void withField(@NonNull String name, @NonNull Consumer<char[]> consumer) {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(consumer, "consumer");
        requireOpen();
        byte @Nullable [] value = fields.get(name);
        if (value == null) {
            throw new ValidationException("Structured secret field does not exist");
        }
        try (SecretBuffer buffer = SecretBuffer.fromUtf8(value)) {
            buffer.copyChars(consumer);
        }
    }

    @Override
    public void close() {
        if (!closed) {
            fields.values().forEach(StructuredSecretViewImpl::wipe);
            fields.clear();
            closed = true;
        }
    }

    private void requireOpen() {
        if (closed) {
            throw new top.focess.keystead.memory.SecretDestroyedException();
        }
    }

    private static @NonNull Map<String, byte[]> copyFields(@NonNull Map<String, byte[]> fields) {
        Map<String, byte[]> copy = new LinkedHashMap<>();
        Objects.requireNonNull(fields, "fields")
                .forEach((key, value) -> copy.put(key, value.clone()));
        return copy;
    }

    private static void wipe(byte @Nullable [] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }
}
