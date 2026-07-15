package top.focess.keystead.memory;

import org.jspecify.annotations.NonNull;

@FunctionalInterface
public interface SecretMemoryProvider {

    @NonNull SecretMemory protect(byte @NonNull [] value);

    static @NonNull SecretMemoryProvider heap() {
        return HeapSecretMemoryProvider.instance();
    }

    static @NonNull SecretMemoryProvider systemDefault() {
        return NativeLockedSecretMemoryProvider.instance();
    }

    static @NonNull SecretMemoryProvider nativeLocked() {
        return NativeLockedSecretMemoryProvider.instance();
    }
}
