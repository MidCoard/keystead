package top.focess.keystead.generator;

import top.focess.keystead.memory.SecretBuffer;

public interface PasswordGenerator {

    SecretBuffer generate(PasswordPolicy policy);
}
