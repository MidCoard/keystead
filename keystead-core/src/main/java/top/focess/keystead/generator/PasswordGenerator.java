package top.focess.keystead.generator;

import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.SecretBuffer;

public interface PasswordGenerator {

    @NonNull SecretBuffer generate(@NonNull PasswordPolicy policy);
}
