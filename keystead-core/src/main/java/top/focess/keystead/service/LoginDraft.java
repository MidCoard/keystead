package top.focess.keystead.service;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.memory.SecretBuffer;

public interface LoginDraft {

    @NonNull LoginDraft title(@NonNull String title);

    @NonNull LoginDraft tag(@Nullable String tag);

    @NonNull LoginDraft username(@NonNull SecretBuffer username);

    @NonNull LoginDraft password(@NonNull SecretBuffer password);

    @NonNull LoginDraft url(@Nullable String url);

    @NonNull LoginDraft notes(@NonNull SecretBuffer notes);
}
