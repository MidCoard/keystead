package top.focess.keystead.model;

import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import org.jspecify.annotations.NonNull;

public record SecretProfile(
        @NonNull String title,
        @NonNull SecretClassification classification,
        @NonNull Set<String> tags,
        @NonNull Map<String, String> attributes) {

    public SecretProfile {
        title = Objects.requireNonNull(title, "title").trim();
        classification = Objects.requireNonNull(classification, "classification");
        tags =
                Objects.requireNonNull(tags, "tags").stream()
                        .map(SecretProfile::normalize)
                        .filter(value -> !value.isBlank())
                        .collect(Collectors.toUnmodifiableSet());
        attributes =
                Objects.requireNonNull(attributes, "attributes").entrySet().stream()
                        .map(
                                entry ->
                                        Map.entry(
                                                normalize(entry.getKey()),
                                                normalize(entry.getValue())))
                        .filter(entry -> !entry.getKey().isBlank() && !entry.getValue().isBlank())
                        .collect(
                                Collectors.toUnmodifiableMap(
                                        Map.Entry::getKey, Map.Entry::getValue));
        if (title.isBlank()) {
            throw new IllegalArgumentException("Secret title must not be blank");
        }
    }

    public SecretProfile(
            @NonNull String title,
            @NonNull SecretClassification classification,
            @NonNull Set<String> tags) {
        this(title, classification, tags, Map.of());
    }

    private static @NonNull String normalize(@NonNull String value) {
        return Objects.requireNonNull(value, "value").trim();
    }
}
