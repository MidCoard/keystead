package top.focess.keystead.security.internal;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.StructLayout;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.memory.NativePlatform;

/**
 * Self-contained Java 25 FFM reads of POSIX process-limit state for {@link HotSpotHardeningOperations}.
 *
 * <p>Reads {@code getrlimit(RLIMIT_CORE)} on Linux and macOS and {@code prctl(PR_GET_DUMPABLE)} on
 * Linux. The {@code struct rlimit} layout matches the reviewed ABI validated by {@code NativeAbi}
 * (16 bytes, two {@code rlim_t} longs). Reads return {@code null} when the platform lacks the call,
 * the symbol cannot be resolved, or the downcall fails, so {@code inspect()} never throws. The
 * mutation downcalls ({@code setrlimit}, {@code prctl(PR_SET_DUMPABLE)}) and their {@code errno}
 * capture are added with subprocess evidence in a later task.
 */
final class PosixHardeningCalls {

    // PR_GET_DUMPABLE, <sys/prctl.h> (Linux UAPI)
    private static final int PR_GET_DUMPABLE = 3;
    // RLIMIT_CORE, <uapi/asm-generic/resource.h> (Linux) and <sys/resource.h> (Darwin): both 4
    private static final int RLIMIT_CORE = 4;

    private static final @NonNull Linker LINKER = Linker.nativeLinker();

    private static final @NonNull StructLayout RLIMIT_LAYOUT =
            MemoryLayout.structLayout(
                    ValueLayout.JAVA_LONG.withName("rlim_cur"),
                    ValueLayout.JAVA_LONG.withName("rlim_max"));

    private static final long RLIM_CUR_OFFSET =
            RLIMIT_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("rlim_cur"));
    private static final long RLIM_MAX_OFFSET =
            RLIMIT_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("rlim_max"));

    private final @Nullable MethodHandle getrlimit;
    private final @Nullable MethodHandle prctl;

    PosixHardeningCalls(@NonNull NativePlatform platform) {
        this.getrlimit = resolveGetrlimit();
        this.prctl = isLinux(platform) ? resolvePrctl() : null;
    }

    private static boolean isLinux(@NonNull NativePlatform platform) {
        return platform == NativePlatform.LINUX_X86_64 || platform == NativePlatform.LINUX_AARCH64;
    }

    private static @Nullable MethodHandle resolveGetrlimit() {
        MemorySegment symbol = LINKER.defaultLookup().find("getrlimit").orElse(null);
        if (symbol == null) {
            return null;
        }
        try {
            return LINKER.downcallHandle(
                    symbol,
                    FunctionDescriptor.of(
                            ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static @Nullable MethodHandle resolvePrctl() {
        MemorySegment symbol = LINKER.defaultLookup().find("prctl").orElse(null);
        if (symbol == null) {
            return null;
        }
        try {
            return LINKER.downcallHandle(
                    symbol,
                    FunctionDescriptor.of(
                            ValueLayout.JAVA_INT,
                            ValueLayout.JAVA_INT,
                            ValueLayout.JAVA_LONG,
                            ValueLayout.JAVA_LONG,
                            ValueLayout.JAVA_LONG,
                            ValueLayout.JAVA_LONG),
                    Linker.Option.firstVariadicArg(1));
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** Linux {@code prctl(PR_GET_DUMPABLE)} value (0, 1, or 2), or {@code null} if unavailable. */
    @Nullable Integer readDumpable() {
        MethodHandle handle = prctl;
        if (handle == null) {
            return null;
        }
        try {
            int value = (int) handle.invoke(PR_GET_DUMPABLE, 0L, 0L, 0L, 0L);
            return value < 0 ? null : value;
        } catch (Throwable t) {
            return null;
        }
    }

    /** POSIX {@code RLIMIT_CORE} soft and hard values, or {@code null} if unavailable. */
    @Nullable CoreLimit readCoreLimit() {
        MethodHandle handle = getrlimit;
        if (handle == null) {
            return null;
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment rlimit = arena.allocate(RLIMIT_LAYOUT);
            int returned = (int) handle.invoke(RLIMIT_CORE, rlimit);
            if (returned < 0) {
                return null;
            }
            long soft = rlimit.get(ValueLayout.JAVA_LONG, RLIM_CUR_OFFSET);
            long hard = rlimit.get(ValueLayout.JAVA_LONG, RLIM_MAX_OFFSET);
            return new CoreLimit(soft, hard);
        } catch (Throwable t) {
            return null;
        }
    }
}
