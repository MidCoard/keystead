package top.focess.keystead.model;

import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Normalized, non-secret taxonomy for a secret: category, provider, software, account, and labels.
 * Taxonomy fields are trimmed and lowercased; blank values become {@code null}. Labels are trimmed,
 * lowercased, and de-duplicated.
 *
 * @param category the optional, lowercased category
 * @param provider the optional, lowercased provider
 * @param software the optional, lowercased software
 * @param account the optional account identifier
 * @param labels the lowercased, de-duplicated label set
 */
public record SecretClassification(
        @Nullable String category,
        @Nullable String provider,
        @Nullable String software,
        @Nullable String account,
        @NonNull Set<String> labels) {

    /** Validates and normalizes the record components. */
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

    /**
     * Constructs a classification with no software and no labels.
     *
     * @param category the optional, lowercased category
     * @param provider the optional, lowercased provider
     * @param account the optional account identifier
     */
    public SecretClassification(
            @Nullable String category, @Nullable String provider, @Nullable String account) {
        this(category, provider, null, account, Set.of());
    }

    /**
     * Constructs a classification with no software and the given labels.
     *
     * @param category the optional, lowercased category
     * @param provider the optional, lowercased provider
     * @param account the optional account identifier
     * @param labels the lowercased, de-duplicated label set
     */
    public SecretClassification(
            @Nullable String category,
            @Nullable String provider,
            @Nullable String account,
            @NonNull Set<String> labels) {
        this(category, provider, null, account, labels);
    }

    /**
     * Constructs a classification with the given software and no labels.
     *
     * @param category the optional, lowercased category
     * @param provider the optional, lowercased provider
     * @param software the optional, lowercased software
     * @param account the optional account identifier
     */
    public SecretClassification(
            @Nullable String category,
            @Nullable String provider,
            @Nullable String software,
            @Nullable String account) {
        this(category, provider, software, account, Set.of());
    }

    /** Returns a classification with all fields empty.
     *
     * @return a classification with no category, provider, software, account, or labels */
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
