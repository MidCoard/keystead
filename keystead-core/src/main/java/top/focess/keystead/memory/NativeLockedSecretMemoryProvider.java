package top.focess.keystead.memory;

import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.internal.NativeSecretMemory;

/**
 * Fail-closed native locked-memory {@link SecretMemoryProvider}.
 *
 * <p>Acquiring the {@link #instance() singleton} has no native side effects; platform resolution,
 * native-access checks, symbol resolution, and allocation occur only when {@link #protect(byte[])}
 * is first used. Native protection never silently falls back to heap memory: a missing prerequisite
 * raises {@link NativeMemoryUnavailableException}.
 */
public final class NativeLockedSecretMemoryProvider implements SecretMemoryProvider {

    private static final @NonNull NativeLockedSecretMemoryProvider INSTANCE =
            new NativeLockedSecretMemoryProvider();

    private NativeLockedSecretMemoryProvider() {}

    public static @NonNull NativeLockedSecretMemoryProvider instance() {
        return INSTANCE;
    }

    @Override
    public @NonNull SecretMemory protect(byte @NonNull [] value) {
        Objects.requireNonNull(value, "value");
        return NativeSecretMemory.protect(value);
    }
}
