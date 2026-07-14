package top.focess.keystead.crypto;

import org.jspecify.annotations.NonNull;

public interface PasswordKeyDerivation {

    @NonNull String algorithm();

    byte @NonNull [] derive(
            char @NonNull [] password, @NonNull KdfParameters parameters, int outputBytes);
}
