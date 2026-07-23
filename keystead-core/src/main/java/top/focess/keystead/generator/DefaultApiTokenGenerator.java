package top.focess.keystead.generator;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.memory.Wipe;

/**
 * Default {@link ApiTokenGenerator} that produces a {@code prefix_base64url(random)} token from a
 * {@link SecureRandom}.
 */
public final class DefaultApiTokenGenerator implements ApiTokenGenerator {

    private final SecureRandom random;

    /** Creates a generator with a default secure random. */
    public DefaultApiTokenGenerator() {
        this(new SecureRandom());
    }

    /**
     * Creates a generator with the supplied secure random.
     *
     * @param random the secure random source
     */
    public DefaultApiTokenGenerator(@NonNull SecureRandom random) {
        this.random = Objects.requireNonNull(random, "random");
    }

    @Override
    public @NonNull SecretBuffer generate(@NonNull ApiTokenPolicy policy) {
        Objects.requireNonNull(policy, "policy");
        byte[] randomBytes = new byte[policy.randomBytes()];
        byte[] encoded = null;
        char[] token = null;
        try {
            random.nextBytes(randomBytes);
            encoded = Base64.getUrlEncoder().withoutPadding().encode(randomBytes);
            byte[] prefix = policy.prefix().getBytes(StandardCharsets.US_ASCII);
            token = new char[prefix.length + 1 + encoded.length];
            int offset = 0;
            for (byte value : prefix) {
                token[offset++] = (char) value;
            }
            token[offset++] = '_';
            for (byte value : encoded) {
                token[offset++] = (char) value;
            }
            return SecretBuffer.fromChars(token);
        } finally {
            Wipe.wipe(randomBytes);
            if (encoded != null) {
                Wipe.wipe(encoded);
            }
            if (token != null) {
                Wipe.wipe(token);
            }
        }
    }
}
