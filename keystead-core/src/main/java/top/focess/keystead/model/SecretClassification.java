package top.focess.keystead.model;

import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

public record SecretClassification(
        @Nullable String category,
        @Nullable String provider,
        @Nullable String software,
        @Nullable String account,
        @NonNull Set<String> labels) {

    public SecretClassification {
        category = normalizeTaxonomy(category);
        provider = normalizeTaxonomy(provider);
        software = normalizeTaxonomy(software);
        account = normalize(account);
        labels =
                Objects.requireNonNull(labels, "labels").stream()
                        .map(SecretClassification::normalizeLabel)
                        .filter(value -> !value.isBlank())
                        .collect(Collectors.toUnmodifiableSet());
    }

    public SecretClassification(
            @Nullable String category, @Nullable String provider, @Nullable String account) {
        this(category, provider, null, account, Set.of());
    }

    public SecretClassification(
            @Nullable String category,
            @Nullable String provider,
            @Nullable String account,
            @NonNull Set<String> labels) {
        this(category, provider, null, account, labels);
    }

    public SecretClassification(
            @Nullable String category,
            @Nullable String provider,
            @Nullable String software,
            @Nullable String account) {
        this(category, provider, software, account, Set.of());
    }

    public static @NonNull SecretClassification none() {
        return new SecretClassification(null, null, null, null, Set.of());
    }

    private static @Nullable String normalize(@Nullable String value) {
        if (value == null) {
            return null;
        }
        String normalized = value.trim();
        return normalized.isBlank() ? null : normalized;
    }

    private static @Nullable String normalizeTaxonomy(@Nullable String value) {
        @Nullable String normalized = normalize(value);
        return normalized == null ? null : normalized.toLowerCase(Locale.ROOT);
    }

    private static @NonNull String normalizeLabel(@NonNull String value) {
        return Objects.requireNonNull(value, "label").trim().toLowerCase(Locale.ROOT);
    }
}
