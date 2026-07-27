package top.focess.keystead.share;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.model.SecretType;

/**
 * The recipient side of a single-secret share: the plaintext payload recovered by
 * {@link ShareService#open(String, char[])}.
 *
 * <p><b>Sensitive.</b> {@code fields} (and possibly {@code sharerNote}) carry plaintext
 * secret material. Because Java {@link String} values cannot be reliably cleared from
 * memory, callers should copy only what they need, render it, and let the {@code String}
 * references go out of scope promptly; avoid retaining {@code ShareContents} instances
 * longer than necessary. {@link #toString()} is redacted to avoid leaking values into logs.
 *
 * <p>The fields map is defensively copied and exposed as an unmodifiable snapshot. Field
 * order mirrors the on-the-wire order (sorted by name at mint time).
 *
 * @param shareId     opaque identifier assigned at mint time (a UUID string)
 * @param secretType  the kind of secret shared
 * @param title       the human label supplied by the sharer
 * @param fields      the recovered secret key/value payload (sensitive)
 * @param sharerNote  the sharer's optional note, may be {@code null}
 * @param createdAt   when the share was minted
 * @param expiresAt   optional expiry instant, may be {@code null}
 */
public record ShareContents(
        @NonNull String shareId,
        @NonNull SecretType secretType,
        @NonNull String title,
        @NonNull Map<String, String> fields,
        @Nullable String sharerNote,
        @NonNull Instant createdAt,
        @Nullable Instant expiresAt) {

    public ShareContents {
        Objects.requireNonNull(shareId, "shareId");
        Objects.requireNonNull(secretType, "secretType");
        Objects.requireNonNull(title, "title");
        Objects.requireNonNull(fields, "fields");
        Objects.requireNonNull(createdAt, "createdAt");
        Map<String, String> copy = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : fields.entrySet()) {
            copy.put(
                    Objects.requireNonNull(entry.getKey(), "field name"),
                    Objects.requireNonNull(entry.getValue(), "field value"));
        }
        fields = Map.copyOf(copy);
    }

    @Override
    public @NonNull String toString() {
        return "ShareContents{shareId="
                + shareId
                + ", secretType="
                + secretType
                + ", title="
                + title
                + ", fields=<redacted:"
                + fields.size()
                + ">"
                + ", hasNote="
                + (sharerNote != null)
                + ", createdAt="
                + createdAt
                + ", expiresAt="
                + expiresAt
                + '}';
    }
}
