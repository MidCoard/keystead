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
            case LINUX_X86_64, LINUX_AARCH64 -> new LinuxNativeOperations(platform);
            case MACOS_X86_64, MACOS_AARCH64 -> new MacOsNativeOperations(platform);
            default ->
                    throw new NativeMemoryUnavailableException(
                            platform, NativeMemoryOperation.SYMBOLS);
        };
    }
}
