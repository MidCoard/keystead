package top.focess.keystead.service;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.memory.SecretBuffer;
import top.focess.keystead.model.SecretClassification;

public interface StructuredSecretDraft {

    @NonNull StructuredSecretDraft title(@NonNull String title);

    @NonNull StructuredSecretDraft tag(@Nullable String tag);

    @NonNull StructuredSecretDraft classification(@NonNull SecretClassification classification);

    @NonNull StructuredSecretDraft attribute(@NonNull String key, @NonNull String value);

    @NonNull StructuredSecretDraft field(@NonNull String name, @NonNull SecretBuffer value);
}
