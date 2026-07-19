package top.focess.keystead.memory;

import org.jspecify.annotations.NonNull;

/**
 * Factory for {@link SecretMemory} holding secret bytes with a defined wipe-on-close lifecycle.
 */
@FunctionalInterface
public interface SecretMemoryProvider {

    /**
     * Protects a copy of {@code value} in secret memory. The caller retains ownership of the
     * supplied array and must wipe it.
     *
     * @param value the secret bytes to protect
     * @return the secret memory owning a protected copy of {@code value}
     */
    @NonNull SecretMemory protect(byte @NonNull [] value);

    /**
     * Returns the heap-backed provider that wipes on close but offers no page-locking guarantee.
     *
     * @return the heap-backed provider
     */
    static @NonNull SecretMemoryProvider heap() {
        return HeapSecretMemoryProvider.instance();
    }

    /**
     * Returns the system default provider: fail-closed native locked memory.
     *
     * @return the system default provider
     */
    static @NonNull SecretMemoryProvider systemDefault() {
        return NativeLockedSecretMemoryProvider.instance();
    }

    /**
     * Returns the fail-closed native locked-memory provider.
     *
     * @return the native locked-memory provider
     */
    static @NonNull SecretMemoryProvider nativeLocked() {
        return NativeLockedSecretMemoryProvider.instance();
    }
}
