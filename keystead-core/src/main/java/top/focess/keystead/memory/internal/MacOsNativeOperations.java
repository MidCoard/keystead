package top.focess.keystead.memory.internal;

import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.NativePlatform;

/**
 * macOS libc backend. Uses the shared POSIX {@code mmap}/{@code mlock}/{@code munlock}/{@code
 * munmap} path with the Darwin {@code MAP_ANON} value. macOS does not receive a Linux-style
 * per-mapping dump-exclusion claim; dump exclusion is reported {@code NOT_APPLICABLE} and never
 * invoked. Constants cite the Darwin SDK headers and are verified by the CI matrix.
 */
final class MacOsNativeOperations extends PosixNativeOperations {

    // _SC_PAGESIZE, <unistd.h> (Darwin). NOTE: Darwin _SC_PAGESIZE is 29, not 47; 47 is
    // _SC_MQ_PRIO_MAX, which macOS returns -1 for (no POSIX message queues) and caused the
    // backend to fail platform setup with operation=PLATFORM on macOS CI.
    private static final int SC_PAGESIZE = 29;
    // MAP_ANON, <sys/mman.h> (Darwin)
    private static final int MAP_ANON = 0x1000;

    MacOsNativeOperations(@NonNull NativePlatform platform) {
        super(platform);
    }

    @Override
    int scPageSize() {
        return SC_PAGESIZE;
    }

    @Override
    int mapAnonymous() {
        return MAP_ANON;
    }

    @Override
    protected @NonNull NativeCallResult dumpExcludeNative(long address, long byteSize) {
        throw new UnsupportedOperationException("dump exclusion is Linux-only");
    }
}
