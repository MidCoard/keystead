package top.focess.keystead.memory.internal;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.util.function.Supplier;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.NativeMemoryOperation;
import top.focess.keystead.memory.NativeMemoryUnavailableException;
import top.focess.keystead.memory.NativePlatform;

/**
 * Shared POSIX libc backend for Linux and macOS. Allocates with {@code mmap(MAP_PRIVATE |
 * MAP_ANON, PROT_READ|PROT_WRITE)}, locks with {@code mlock}, unlocks with {@code munlock}, and
 * releases with {@code munmap}. {@code errno} is captured per fallible downcall. Page size is read
 * with {@code sysconf(_SC_PAGESIZE)}. Dump exclusion ({@code madvise}) is Linux-only and supplied
 * by subclasses; {@code copyIn}/{@code wipe} are inherited.
 */
abstract class PosixNativeOperations extends PlatformNativeOperations {

    private static final int PROT_READ = 0x1;
    private static final int PROT_WRITE = 0x2;
    private static final int MAP_PRIVATE = 0x02;

    private final @NonNull Arena arena = Arena.ofShared();
    private final @NonNull MethodHandle mmap;
    private final @NonNull MethodHandle mlock;
    private final @NonNull MethodHandle munlock;
    private final @NonNull MethodHandle munmap;
    private final @NonNull MethodHandle sysconf;
    private final long pageSize;

    PosixNativeOperations(@NonNull NativePlatform platform) {
        super(platform);
        FfmSupport.requireAbi(platform);
        SymbolLookup libc = FfmSupport.LINKER.defaultLookup();
        Supplier<NativeMemoryUnavailableException> missing =
                () -> FfmSupport.symbolsUnavailable(platform);
        Linker.Option capture = FfmSupport.captureCallState(platform);
        try {
            this.mmap =
                    FfmSupport.LINKER.downcallHandle(
                            libc.find("mmap").orElseThrow(missing),
                            FunctionDescriptor.of(
                                    ValueLayout.ADDRESS,
                                    ValueLayout.ADDRESS,
                                    ValueLayout.JAVA_LONG,
                                    ValueLayout.JAVA_INT,
                                    ValueLayout.JAVA_INT,
                                    ValueLayout.JAVA_INT,
                                    ValueLayout.JAVA_LONG),
                            capture);
            this.mlock =
                    FfmSupport.LINKER.downcallHandle(
                            libc.find("mlock").orElseThrow(missing),
                            FunctionDescriptor.of(
                                    ValueLayout.JAVA_INT,
                                    ValueLayout.ADDRESS,
                                    ValueLayout.JAVA_LONG),
                            capture);
            this.munlock =
                    FfmSupport.LINKER.downcallHandle(
                            libc.find("munlock").orElseThrow(missing),
                            FunctionDescriptor.of(
                                    ValueLayout.JAVA_INT,
                                    ValueLayout.ADDRESS,
                                    ValueLayout.JAVA_LONG),
                            capture);
            this.munmap =
                    FfmSupport.LINKER.downcallHandle(
                            libc.find("munmap").orElseThrow(missing),
                            FunctionDescriptor.of(
                                    ValueLayout.JAVA_INT,
                                    ValueLayout.ADDRESS,
                                    ValueLayout.JAVA_LONG),
                            capture);
            this.sysconf =
                    FfmSupport.LINKER.downcallHandle(
                            libc.find("sysconf").orElseThrow(missing),
                            FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT),
                            capture);
        } catch (IllegalArgumentException e) {
            throw FfmSupport.symbolsUnavailable(platform);
        }
        this.pageSize = readPageSize();
    }

    /** glibc/Darwin {@code _SC_PAGESIZE} constant for the target OS. */
    abstract int scPageSize();

    /** {@code MAP_ANON} (Linux {@code MAP_ANONYMOUS}) value for the target OS. */
    abstract int mapAnonymous();

    @Override
    public long pageSize() {
        return pageSize;
    }

    @Override
    protected final @NonNull NativeCallResult allocateNative(long byteSize) {
        int protection = PROT_READ | PROT_WRITE;
        int flags = MAP_PRIVATE | mapAnonymous();
        try (Arena call = Arena.ofConfined()) {
            MemorySegment capture = call.allocate(FfmSupport.CAPTURE_STATE_LAYOUT);
            MemorySegment result =
                    (MemorySegment)
                            mmap.invoke(
                                    capture,
                                    MemorySegment.NULL,
                                    byteSize,
                                    protection,
                                    flags,
                                    -1,
                                    0L);
            long errno = Integer.toUnsignedLong(capture.get(ValueLayout.JAVA_INT, errnoOffset()));
            return new NativeCallResult(result.address(), errno);
        } catch (Throwable t) {
            throw FfmSupport.rethrow(t);
        }
    }

    @Override
    protected final @NonNull NativeCallResult lockNative(long address, long byteSize) {
        return callInt(mlock, address, byteSize);
    }

    @Override
    protected final @NonNull NativeCallResult unlockNative(long address, long byteSize) {
        return callInt(munlock, address, byteSize);
    }

    @Override
    protected final @NonNull NativeCallResult releaseNative(long address, long byteSize) {
        return callInt(munmap, address, byteSize);
    }

    protected final long errnoOffset() {
        return FfmSupport.captureStateOffset(platform());
    }

    protected final @NonNull NativeCallResult callInt(
            @NonNull MethodHandle handle, long address, long byteSize) {
        try (Arena call = Arena.ofConfined()) {
            MemorySegment capture = call.allocate(FfmSupport.CAPTURE_STATE_LAYOUT);
            int returned = (int) handle.invoke(capture, MemorySegment.ofAddress(address), byteSize);
            long errno = Integer.toUnsignedLong(capture.get(ValueLayout.JAVA_INT, errnoOffset()));
            return new NativeCallResult(returned, errno);
        } catch (Throwable t) {
            throw FfmSupport.rethrow(t);
        }
    }

    private long readPageSize() {
        try (Arena call = Arena.ofConfined()) {
            MemorySegment capture = call.allocate(FfmSupport.CAPTURE_STATE_LAYOUT);
            long size = (long) sysconf.invoke(capture, scPageSize());
            if (size <= 0L || (size & (size - 1L)) != 0L) {
                throw new NativeMemoryUnavailableException(
                        platform(), NativeMemoryOperation.PLATFORM);
            }
            return size;
        } catch (Throwable t) {
            throw FfmSupport.rethrow(t);
        }
    }
}
