package top.focess.keystead.service;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.model.SecretClassification;

public interface LoginDraft {

    @NonNull LoginDraft title(@NonNull String title);

    @NonNull LoginDraft tag(@Nullable String tag);

    @NonNull LoginDraft classification(@NonNull SecretClassification classification);

    @NonNull LoginDraft attribute(@NonNull String key, @NonNull String value);

    @NonNull LoginDraft username(@NonNull SecretBuffer username);

    @NonNull LoginDraft password(@NonNull SecretBuffer password);

    @NonNull LoginDraft url(@Nullable String url);

    @NonNull LoginDraft notes(@NonNull SecretBuffer notes);
}
