package top.focess.keystead.generator;

import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.SecretBuffer;

/**
 * Generates an API token conforming to a {@link ApiTokenPolicy}, returning it as an owned {@link
 * SecretBuffer}.
 */
public interface ApiTokenGenerator {

    /**
     * Generates an API token for the given policy.
     *
     * @param policy the token policy
     * @return the generated token
     */
    @NonNull SecretBuffer generate(@NonNull ApiTokenPolicy policy);
}
