package top.focess.keystead.service;

import java.util.Set;
import java.util.function.Consumer;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.SecretMetadata;

public interface StructuredSecretView {

    @NonNull SecretMetadata metadata();

    @NonNull Set<String> fieldNames();

    void withField(@NonNull String name, @NonNull Consumer<char[]> consumer);
}
