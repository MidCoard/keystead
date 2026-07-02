package top.focess.keystead.service;

import java.util.Optional;
import java.util.function.Consumer;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.SecretMetadata;

public interface LoginSecretView {

    @NonNull SecretMetadata metadata();

    @NonNull Optional<String> url();

    void withUsername(@NonNull Consumer<char[]> consumer);

    void withPassword(@NonNull Consumer<char[]> consumer);

    void withNotes(@NonNull Consumer<char[]> consumer);
}
