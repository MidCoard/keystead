package top.focess.keystead.generator;

import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.SecretBuffer;

public interface ApiTokenGenerator {

    @NonNull SecretBuffer generate(@NonNull ApiTokenPolicy policy);
}
