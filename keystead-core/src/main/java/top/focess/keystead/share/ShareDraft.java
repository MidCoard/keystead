package top.focess.keystead.share;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.model.SecretType;

/**
 * The mint side of a single-secret share: everything needed to produce a
 * {@code keystead-share:v1:...} string via {@link ShareService#create(ShareDraft, char[])}.
 *
 * <p>{@code fields} is the secret payload the recipient will recover (for a login that is
 * typically {@code url/username/password/notes} keyed however the caller prefers). The map
 * is defensively copied and exposed as an unmodifiable, insertion-ordered snapshot. Field
 * keys and values are <em>not</em> validated against {@code secretType}'s schema; a share is
 * a field-agnostic transport, so the caller's key set is recovered verbatim by the recipient.
 *
 * <p>{@code kdfIterations} selects the PBKDF2 cost; {@code 0} means "use the format default".
 * Values below {@link top.focess.keystead.model.SecurityLimits#SHARE_PBKDF2_MIN_ITERATIONS}
 * are rejected at mint time.
 *
 * <p>{@code expiresAt} is optional; when present, {@link ShareService#open(String, char[])}
 * refuses to decrypt an expired share.
 *
 * @param secretType   the kind of secret being shared (round-tripped to the recipient)
 * @param title        a short, non-blank human label (trimmed)
 * @param fields       the secret key/value payload; non-null keys and values, no blank keys
 * @param sharerNote   optional free-form note from the sharer, may be {@code null}
 * @param expiresAt    optional expiry instant, may be {@code null}
 * @param kdfIterations PBKDF2 iteration count, or {@code 0} for the format default
 */
public record ShareDraft(
        @NonNull SecretType secretType,
        @NonNull String title,
        @NonNull Map<String, String> fields,
        @Nullable String sharerNote,
        @Nullable Instant expiresAt,
        int kdfIterations) {

    public ShareDraft {
        Objects.requireNonNull(secretType, "secretType");
        Objects.requireNonNull(title, "title");
        Objects.requireNonNull(fields, "fields");
        if (kdfIterations < 0) {
            throw new IllegalArgumentException("Share kdfIterations must not be negative");
        }
        String trimmed = title.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("Share title must not be blank");
        }
        Map<String, String> copy = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : fields.entrySet()) {
            String name = Objects.requireNonNull(entry.getKey(), "field name");
            if (name.isBlank()) {
                throw new IllegalArgumentException("Share field name must not be blank");
            }
            Objects.requireNonNull(entry.getValue(), "field value for '" + name + "'");
            copy.put(name, entry.getValue());
        }
        title = trimmed;
        fields = Collections.unmodifiableMap(copy);
    }

    /**
     * Convenience constructor for a non-expiring share using the default KDF cost.
     *
     * @param secretType the kind of secret being shared
     * @param title      a short, non-blank human label
     * @param fields     the secret key/value payload
     */
    public ShareDraft(
            @NonNull SecretType secretType,
            @NonNull String title,
            @NonNull Map<String, String> fields) {
        this(secretType, title, fields, null, null, 0);
    }
}
