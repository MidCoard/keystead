package top.focess.keystead.generator;

import org.jspecify.annotations.NonNull;

public interface GpgKeyGenerator {
    @NonNull GpgKeyPair generate(@NonNull GpgKeyPolicy policy);
}
