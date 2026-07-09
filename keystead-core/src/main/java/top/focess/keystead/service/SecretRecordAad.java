package top.focess.keystead.service;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.model.SecretMetadata;
import top.focess.keystead.model.VaultId;

final class SecretRecordAad {

    private SecretRecordAad() {}

    static byte @NonNull [] encode(
            @NonNull VaultId vaultId, @NonNull SecretMetadata metadata, long revision) {
        StringBuilder value = new StringBuilder();
        append(value, "keystead-secret-record-v2");
        append(value, vaultId.value().toString());
        append(value, metadata.id().value().toString());
        append(value, metadata.type().name());
        append(value, metadata.title());
        append(value, nullable(metadata.classification().category()));
        append(value, nullable(metadata.classification().provider()));
        if (metadata.classification().software() != null) {
            append(value, metadata.classification().software());
        }
        append(value, nullable(metadata.classification().account()));
        append(value, Integer.toString(metadata.classification().labels().size()));
        metadata.classification().labels().stream().sorted().forEach(label -> append(value, label));
        append(value, Integer.toString(metadata.tags().size()));
        metadata.tags().stream().sorted().forEach(tag -> append(value, tag));
        append(value, Integer.toString(metadata.profile().attributes().size()));
        metadata.profile().attributes().entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(
                        entry -> {
                            append(value, entry.getKey());
                            append(value, entry.getValue());
                        });
        append(value, metadata.createdAt().toString());
        append(value, metadata.updatedAt().toString());
        append(value, Long.toString(metadata.revision()));
        append(value, Long.toString(revision));
        return value.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static void append(@NonNull StringBuilder builder, @NonNull String value) {
        builder.append(value.length()).append(':').append(value).append('|');
    }

    private static @NonNull String nullable(@Nullable String value) {
        return value == null ? "" : value;
    }
}
