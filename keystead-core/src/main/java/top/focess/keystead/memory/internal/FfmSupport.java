package top.focess.keystead.memory.internal;

import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.StructLayout;
import java.lang.foreign.ValueLayout;
import java.util.HashMap;
import java.util.Map;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.NativeMemoryOperation;
import top.focess.keystead.memory.NativeMemoryUnavailableException;
import top.focess.keystead.memory.NativePlatform;

/** Shared Java 25 FFM helpers used by every platform backend. */
final class FfmSupport {

    static final @NonNull Linker LINKER = Linker.nativeLinker();
    static final @NonNull StructLayout CAPTURE_STATE_LAYOUT = Linker.Option.captureStateLayout();

    private FfmSupport() {}

    static @NonNull Map<@NonNull String, @NonNull MemoryLayout> canonicalLayouts(
            @NonNull NativePlatform platform) {
        Map<String, MemoryLayout> layouts = new HashMap<>(LINKER.canonicalLayouts());
        if (platform != NativePlatform.WINDOWS_X86_64) {
            layouts.put("off_t", ValueLayout.JAVA_LONG.withName("off_t"));
            layouts.put("rlim_t", ValueLayout.JAVA_LONG.withName("rlim_t"));
        }
        return layouts;
    }

    static void requireAbi(@NonNull NativePlatform platform) {
        try {
            NativeAbi.requireCanonicalLayouts(platform, canonicalLayouts(platform));
            NativeAbi.requireCaptureStateName(
                    CAPTURE_STATE_LAYOUT, NativeAbi.captureStateName(platform));
        } catch (IllegalArgumentException e) {
            throw new NativeMemoryUnavailableException(platform, NativeMemoryOperation.ABI_LAYOUTS);
        }
    }

    static long captureStateOffset(@NonNull NativePlatform platform) {
        return CAPTURE_STATE_LAYOUT.byteOffset(
                MemoryLayout.PathElement.groupElement(NativeAbi.captureStateName(platform)));
    }

    static Linker.@NonNull Option captureCallState(@NonNull NativePlatform platform) {
        return Linker.Option.captureCallState(NativeAbi.captureStateName(platform));
    }

    static @NonNull NativeMemoryUnavailableException symbolsUnavailable(
            @NonNull NativePlatform platform) {
        return new NativeMemoryUnavailableException(platform, NativeMemoryOperation.SYMBOLS);
    }

    static @NonNull RuntimeException rethrow(@NonNull Throwable throwable) {
        if (throwable instanceof RuntimeException runtime) {
            throw runtime;
        }
        if (throwable instanceof Error error) {
            throw error;
        }
        return new RuntimeException(throwable);
    }
}
