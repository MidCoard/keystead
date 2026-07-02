package top.focess.keystead.service;

import java.util.function.Consumer;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.model.SecretMetadata;

public interface SecureNoteView {

    @NonNull SecretMetadata metadata();

    void withBody(@NonNull Consumer<char[]> consumer);
}
