package top.focess.keystead.service;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.model.SecretClassification;

public interface SecureNoteDraft {

    @NonNull SecureNoteDraft title(@NonNull String title);

    @NonNull SecureNoteDraft tag(@Nullable String tag);

    @NonNull SecureNoteDraft classification(@NonNull SecretClassification classification);

    @NonNull SecureNoteDraft body(@NonNull SecretBuffer body);
}
