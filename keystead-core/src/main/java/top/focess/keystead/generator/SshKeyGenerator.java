package top.focess.keystead.generator;

import org.jspecify.annotations.NonNull;

public interface SshKeyGenerator {

    @NonNull SshKeyPair generate(@NonNull SshKeyPolicy policy);
}
