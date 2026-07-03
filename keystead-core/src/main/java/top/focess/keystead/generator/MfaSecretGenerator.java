package top.focess.keystead.generator;

import org.jspecify.annotations.NonNull;

public interface MfaSecretGenerator {

    @NonNull MfaSecret generate(@NonNull MfaSecretPolicy policy);
}
