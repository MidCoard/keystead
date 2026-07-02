package top.focess.keystead.service;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.memory.SecretBuffer;

public interface SecureNoteDraft {

    @NonNull SecureNoteDraft title(@NonNull String title);

    @NonNull SecureNoteDraft tag(@Nullable String tag);

    @NonNull SecureNoteDraft body(@NonNull SecretBuffer body);
}
