package top.focess.keystead.memory;

import java.util.Arrays;
import org.jspecify.annotations.Nullable;

/**
 * Best-effort zeroing of heap-allocated secret byte arrays after use.
 *
 * <p>This is a defense-in-depth measure that shortens the window during which secret material
 * remains live on the Java heap. It is <em>not</em> a guarantee: the garbage collector and the JIT
 * may move or eliminate dead stores, and the platform may already have copied a secret elsewhere.
 * For strongly protected secret storage prefer {@link SecretBuffer}, which backs secrets with native
 * locked memory where available.
 *
 * <p>The {@link #wipe(byte[])} method is null-safe: a {@code null} reference is ignored.
 */
public final class Wipe {

    private Wipe() {}

    /**
     * Overwrites every byte of {@code value} with zero.
     *
     * <p>This is a best-effort heap zeroing helper; see the class documentation for its limits. It
     * does nothing when {@code value} is {@code null}.
     *
     * @param value the byte array to zero, or {@code null} to do nothing
     */
    public static void wipe(byte @Nullable [] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }
}
