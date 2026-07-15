package top.focess.keystead.memory.internal;

import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.NativeMemoryOperation;
import top.focess.keystead.memory.NativeMemoryUnavailableException;
import top.focess.keystead.memory.NativePlatform;

/** Resolves the real platform {@link NativeOperations} backend for the current platform. */
final class NativeBackends {

    private NativeBackends() {}

    static @NonNull NativeOperations create(@NonNull NativePlatform platform) {
        return switch (platform) {
            case WINDOWS_X86_64 -> new WindowsNativeOperations();
            // Linux and macOS FFM backends are wired in the following task.
            default ->
                    throw new NativeMemoryUnavailableException(
                            platform, NativeMemoryOperation.SYMBOLS);
        };
    }
}
