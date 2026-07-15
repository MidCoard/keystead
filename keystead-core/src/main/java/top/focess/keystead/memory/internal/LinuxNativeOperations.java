package top.focess.keystead.memory.internal;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.NativePlatform;

/**
 * Linux libc backend. Extends the shared POSIX backend with {@code madvise(MADV_DONTDUMP)} dump
 * exclusion. Constants cite the Linux UAPI/glibc headers.
 */
final class LinuxNativeOperations extends PosixNativeOperations {

    // MADV_DONTDUMP, <sys/mman.h> (Linux UAPI)
    private static final int MADV_DONTDUMP = 16;
    // _SC_PAGESIZE, <unistd.h> (glibc)
    private static final int SC_PAGESIZE = 30;
    // MAP_ANONYMOUS, <sys/mman.h> (Linux UAPI)
    private static final int MAP_ANONYMOUS = 0x20;

    private final @NonNull MethodHandle madvise;

    LinuxNativeOperations(@NonNull NativePlatform platform) {
        super(platform);
        Linker.Option capture = FfmSupport.captureCallState(platform);
        try {
            this.madvise =
                    FfmSupport.LINKER.downcallHandle(
                            FfmSupport.LINKER
                                    .defaultLookup()
                                    .find("madvise")
                                    .orElseThrow(() -> FfmSupport.symbolsUnavailable(platform)),
                            FunctionDescriptor.of(
                                    ValueLayout.JAVA_INT,
                                    ValueLayout.ADDRESS,
                                    ValueLayout.JAVA_LONG,
                                    ValueLayout.JAVA_INT),
                            capture);
        } catch (IllegalArgumentException e) {
            throw FfmSupport.symbolsUnavailable(platform);
        }
    }

    @Override
    int scPageSize() {
        return SC_PAGESIZE;
    }

    @Override
    int mapAnonymous() {
        return MAP_ANONYMOUS;
    }

    @Override
    protected @NonNull NativeCallResult dumpExcludeNative(long address, long byteSize) {
        try (Arena call = Arena.ofConfined()) {
            MemorySegment capture = call.allocate(FfmSupport.CAPTURE_STATE_LAYOUT);
            int returned =
                    (int)
                            madvise.invoke(
                                    capture,
                                    MemorySegment.ofAddress(address),
                                    byteSize,
                                    MADV_DONTDUMP);
            long errno = Integer.toUnsignedLong(capture.get(ValueLayout.JAVA_INT, errnoOffset()));
            return new NativeCallResult(returned, errno);
        } catch (Throwable t) {
            throw FfmSupport.rethrow(t);
        }
    }
}
