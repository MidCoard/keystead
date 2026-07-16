package top.focess.keystead.memory.internal;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.memory.NativeMemoryOperation;
import top.focess.keystead.memory.NativeMemoryUnavailableException;
import top.focess.keystead.memory.NativePlatform;

/**
 * Resolves the real platform {@link NativeOperations} backend for the current platform.
 *
 * <p>The backend is stateless after construction (it holds only native symbol handles and the page
 * size), so it is cached as a process-wide singleton. This avoids constructing a fresh backend -
 * and a fresh backend-owned {@link java.lang.foreign.Arena} (the Windows {@code kernel32} library
 * lookup, which has no close hook) - on every {@code protect()} call, which would leak one arena
 * per secret.
 */
final class NativeBackends {

    private NativeBackends() {}

    private static @Nullable NativeOperations cached;

    static synchronized @NonNull NativeOperations create(@NonNull NativePlatform platform) {
        NativeOperations existing = cached;
        if (existing != null) {
            return existing;
        }
        NativeOperations created =
                switch (platform) {
                    case WINDOWS_X86_64 -> new WindowsNativeOperations();
                    case LINUX_X86_64, LINUX_AARCH64 -> new LinuxNativeOperations(platform);
                    case MACOS_X86_64, MACOS_AARCH64 -> new MacOsNativeOperations(platform);
                    default ->
                            throw new NativeMemoryUnavailableException(
                                    platform, NativeMemoryOperation.SYMBOLS);
                };
        cached = created;
        return created;
    }
}
