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
 * Self-contained Java 25 FFM reads and mutations of POSIX process-limit state for {@link
 * HotSpotHardeningOperations}.
 *
 * <p>Reads {@code getrlimit(RLIMIT_CORE)} on Linux and macOS and {@code prctl(PR_GET_DUMPABLE)} on
 * Linux; mutates with {@code setrlimit(RLIMIT_CORE, 0, 0)} on Linux and macOS and {@code
 * prctl(PR_SET_DUMPABLE, 0)} on Linux. The {@code struct rlimit} layout matches the reviewed ABI
 * validated by {@code NativeAbi} (16 bytes, two {@code rlim_t} longs). Every fallible downcall
 * captures {@code errno}; reads return {@code null} on failure (reported {@code UNAVAILABLE}) and
 * mutations return a redacted {@link MutationResult} carrying the unsigned {@code errno} on failure,
 * so {@code inspect()} and {@code applyStrict()} never propagate an unchecked FFM failure. The hard
 * {@code RLIMIT_CORE} mutation is irreversible for an unprivileged process and must run only in
 * expendable child JVMs.
 */
final class PosixHardeningCalls {

    // PR_GET_DUMPABLE, <sys/prctl.h> (Linux UAPI)
    private static final int PR_GET_DUMPABLE = 3;
    // PR_SET_DUMPABLE, <sys/prctl.h> (Linux UAPI)
    private static final int PR_SET_DUMPABLE = 4;
    // RLIMIT_CORE, <uapi/asm-generic/resource.h> (Linux) and <sys/resource.h> (Darwin): both 4
    private static final int RLIMIT_CORE = 4;

    private static final @NonNull Linker LINKER = Linker.nativeLinker();
    private static final @NonNull MemoryLayout CAPTURE_STATE_LAYOUT =
            Linker.Option.captureStateLayout();
    private static final long ERRNO_OFFSET =
            CAPTURE_STATE_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("errno"));
    private static final Linker.@NonNull Option CAPTURE_ERRNO =
            Linker.Option.captureCallState("errno");

    private static final @NonNull StructLayout RLIMIT_LAYOUT =
            MemoryLayout.structLayout(
                    ValueLayout.JAVA_LONG.withName("rlim_cur"),
                    ValueLayout.JAVA_LONG.withName("rlim_max"));
    private static final long RLIM_CUR_OFFSET =
            RLIMIT_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("rlim_cur"));
    private static final long RLIM_MAX_OFFSET =
            RLIMIT_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("rlim_max"));

    private final @Nullable MethodHandle getrlimit;
    private final @Nullable MethodHandle setrlimit;
    private final @Nullable MethodHandle prctl;

    PosixHardeningCalls(@NonNull NativePlatform platform) {
        this.getrlimit =
                resolve(
                        "getrlimit",
                        FunctionDescriptor.of(
                                ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS),
                        CAPTURE_ERRNO);
        this.setrlimit =
                resolve(
                        "setrlimit",
                        FunctionDescriptor.of(
                                ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS),
                        CAPTURE_ERRNO);
        this.prctl =
                isLinux(platform)
                        ? resolve(
                                "prctl",
                                FunctionDescriptor.of(
                                        ValueLayout.JAVA_INT,
                                        ValueLayout.JAVA_INT,
                                        ValueLayout.JAVA_LONG,
                                        ValueLayout.JAVA_LONG,
                                        ValueLayout.JAVA_LONG,
                                        ValueLayout.JAVA_LONG),
                                CAPTURE_ERRNO,
                                Linker.Option.firstVariadicArg(1))
                        : null;
    }

    private static boolean isLinux(@NonNull NativePlatform platform) {
        return platform == NativePlatform.LINUX_X86_64 || platform == NativePlatform.LINUX_AARCH64;
    }

    private static @Nullable MethodHandle resolve(
            @NonNull String symbol,
            @NonNull FunctionDescriptor descriptor,
            Linker.@NonNull Option... options) {
        MemorySegment address = LINKER.defaultLookup().find(symbol).orElse(null);
        if (address == null) {
            return null;
        }
        try {
            return LINKER.downcallHandle(address, descriptor, options);
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
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment capture = arena.allocate(CAPTURE_STATE_LAYOUT);
            int value = (int) handle.invoke(capture, PR_GET_DUMPABLE, 0L, 0L, 0L, 0L);
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
            MemorySegment capture = arena.allocate(CAPTURE_STATE_LAYOUT);
            MemorySegment rlimit = arena.allocate(RLIMIT_LAYOUT);
            int returned = (int) handle.invoke(capture, RLIMIT_CORE, rlimit);
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

    /** Linux {@code prctl(PR_SET_DUMPABLE, 0)}. */
    @NonNull MutationResult setDumpableZero() {
        MethodHandle handle = prctl;
        if (handle == null) {
            return MutationResult.failure(0L);
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment capture = arena.allocate(CAPTURE_STATE_LAYOUT);
            int returned = (int) handle.invoke(capture, PR_SET_DUMPABLE, 0L, 0L, 0L, 0L);
            return returned == 0 ? MutationResult.success() : failureErrno(capture);
        } catch (Throwable t) {
            return MutationResult.failure(0L);
        }
    }

    /** POSIX {@code setrlimit(RLIMIT_CORE, 0, 0)}. */
    @NonNull MutationResult setCoreLimitZero() {
        MethodHandle handle = setrlimit;
        if (handle == null) {
            return MutationResult.failure(0L);
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment capture = arena.allocate(CAPTURE_STATE_LAYOUT);
            MemorySegment rlimit = arena.allocate(RLIMIT_LAYOUT);
            rlimit.set(ValueLayout.JAVA_LONG, RLIM_CUR_OFFSET, 0L);
            rlimit.set(ValueLayout.JAVA_LONG, RLIM_MAX_OFFSET, 0L);
            int returned = (int) handle.invoke(capture, RLIMIT_CORE, rlimit);
            return returned == 0 ? MutationResult.success() : failureErrno(capture);
        } catch (Throwable t) {
            return MutationResult.failure(0L);
        }
    }

    private static @NonNull MutationResult failureErrno(@NonNull MemorySegment capture) {
        long errno = Integer.toUnsignedLong(capture.get(ValueLayout.JAVA_INT, ERRNO_OFFSET));
        return MutationResult.failure(errno);
    }
}
