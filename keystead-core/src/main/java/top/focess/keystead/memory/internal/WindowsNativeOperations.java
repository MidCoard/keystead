package top.focess.keystead.memory.internal;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
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
 * Windows x86-64 Kernel32 backend. Allocates with {@code VirtualAlloc(MEM_RESERVE|MEM_COMMIT,
 * PAGE_READWRITE)}, locks with {@code VirtualLock}, wipes with volatile byte writes, and releases
 * with {@code VirtualFree(MEM_RELEASE)}. {@code GetLastError} is captured per fallible downcall.
 */
final class WindowsNativeOperations extends PlatformNativeOperations {

    private static final int MEM_RESERVE = 0x00002000;
    private static final int MEM_COMMIT = 0x00001000;
    private static final int MEM_RELEASE = 0x00008000;
    private static final int PAGE_READWRITE = 0x00000004;

    private final @NonNull Arena arena = Arena.ofShared();
    private final @NonNull MethodHandle virtualAlloc;
    private final @NonNull MethodHandle virtualLock;
    private final @NonNull MethodHandle virtualUnlock;
    private final @NonNull MethodHandle virtualFree;
    private final long lastErrorOffset;
    private final long pageSize;

    WindowsNativeOperations() {
        super(NativePlatform.WINDOWS_X86_64);
        FfmSupport.requireAbi(NativePlatform.WINDOWS_X86_64);
        SymbolLookup kernel32;
        try {
            kernel32 = SymbolLookup.libraryLookup("kernel32", arena);
        } catch (IllegalArgumentException e) {
            throw FfmSupport.symbolsUnavailable(NativePlatform.WINDOWS_X86_64);
        }
        Linker.Option capture = FfmSupport.captureCallState(NativePlatform.WINDOWS_X86_64);
        this.lastErrorOffset = FfmSupport.captureStateOffset(NativePlatform.WINDOWS_X86_64);
        Supplier<NativeMemoryUnavailableException> missing =
                () -> FfmSupport.symbolsUnavailable(NativePlatform.WINDOWS_X86_64);
        try {
            this.virtualAlloc =
                    FfmSupport.LINKER.downcallHandle(
                            kernel32.find("VirtualAlloc").orElseThrow(missing),
                            FunctionDescriptor.of(
                                    ValueLayout.ADDRESS,
                                    ValueLayout.ADDRESS,
                                    ValueLayout.JAVA_LONG,
                                    ValueLayout.JAVA_INT,
                                    ValueLayout.JAVA_INT),
                            capture);
            this.virtualLock =
                    FfmSupport.LINKER.downcallHandle(
                            kernel32.find("VirtualLock").orElseThrow(missing),
                            FunctionDescriptor.of(
                                    ValueLayout.JAVA_INT,
                                    ValueLayout.ADDRESS,
                                    ValueLayout.JAVA_LONG),
                            capture);
            this.virtualUnlock =
                    FfmSupport.LINKER.downcallHandle(
                            kernel32.find("VirtualUnlock").orElseThrow(missing),
                            FunctionDescriptor.of(
                                    ValueLayout.JAVA_INT,
                                    ValueLayout.ADDRESS,
                                    ValueLayout.JAVA_LONG),
                            capture);
            this.virtualFree =
                    FfmSupport.LINKER.downcallHandle(
                            kernel32.find("VirtualFree").orElseThrow(missing),
                            FunctionDescriptor.of(
                                    ValueLayout.JAVA_INT,
                                    ValueLayout.ADDRESS,
                                    ValueLayout.JAVA_LONG,
                                    ValueLayout.JAVA_INT),
                            capture);
        } catch (IllegalArgumentException e) {
            throw FfmSupport.symbolsUnavailable(NativePlatform.WINDOWS_X86_64);
        }
        this.pageSize = readPageSize(kernel32);
    }

    @Override
    public long pageSize() {
        return pageSize;
    }

    @Override
    protected @NonNull NativeCallResult allocateNative(long byteSize) {
        try (Arena call = Arena.ofConfined()) {
            MemorySegment capture = call.allocate(FfmSupport.CAPTURE_STATE_LAYOUT);
            MemorySegment result =
                    (MemorySegment)
                            virtualAlloc.invoke(
                                    capture,
                                    MemorySegment.NULL,
                                    byteSize,
                                    MEM_RESERVE | MEM_COMMIT,
                                    PAGE_READWRITE);
            long lastError =
                    Integer.toUnsignedLong(capture.get(ValueLayout.JAVA_INT, lastErrorOffset));
            return new NativeCallResult(result.address(), lastError);
        } catch (Throwable t) {
            throw FfmSupport.rethrow(t);
        }
    }

    @Override
    protected @NonNull NativeCallResult lockNative(long address, long byteSize) {
        return callBoolReturningInt(address, byteSize, virtualLock);
    }

    @Override
    protected @NonNull NativeCallResult dumpExcludeNative(long address, long byteSize) {
        throw new UnsupportedOperationException("dump exclusion is Linux-only");
    }

    @Override
    protected @NonNull NativeCallResult unlockNative(long address, long byteSize) {
        return callBoolReturningInt(address, byteSize, virtualUnlock);
    }

    @Override
    protected @NonNull NativeCallResult releaseNative(long address, long byteSize) {
        try (Arena call = Arena.ofConfined()) {
            MemorySegment capture = call.allocate(FfmSupport.CAPTURE_STATE_LAYOUT);
            int returned =
                    (int)
                            virtualFree.invoke(
                                    capture, MemorySegment.ofAddress(address), 0L, MEM_RELEASE);
            long lastError =
                    Integer.toUnsignedLong(capture.get(ValueLayout.JAVA_INT, lastErrorOffset));
            return new NativeCallResult(returned, lastError);
        } catch (Throwable t) {
            throw FfmSupport.rethrow(t);
        }
    }

    private @NonNull NativeCallResult callBoolReturningInt(
            long address, long byteSize, @NonNull MethodHandle handle) {
        try (Arena call = Arena.ofConfined()) {
            MemorySegment capture = call.allocate(FfmSupport.CAPTURE_STATE_LAYOUT);
            int returned = (int) handle.invoke(capture, MemorySegment.ofAddress(address), byteSize);
            long lastError =
                    Integer.toUnsignedLong(capture.get(ValueLayout.JAVA_INT, lastErrorOffset));
            return new NativeCallResult(returned, lastError);
        } catch (Throwable t) {
            throw FfmSupport.rethrow(t);
        }
    }

    private long readPageSize(@NonNull SymbolLookup kernel32) {
        MethodHandle getSystemInfo =
                FfmSupport.LINKER.downcallHandle(
                        kernel32.find("GetSystemInfo")
                                .orElseThrow(
                                        () ->
                                                FfmSupport.symbolsUnavailable(
                                                        NativePlatform.WINDOWS_X86_64)),
                        FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
        MemoryLayout systemInfo =
                NativeAbi.windowsSystemInfoLayout(
                        FfmSupport.canonicalLayouts(NativePlatform.WINDOWS_X86_64));
        long pageSizeOffset =
                systemInfo.byteOffset(MemoryLayout.PathElement.groupElement("dwPageSize"));
        try (Arena call = Arena.ofConfined()) {
            MemorySegment info = call.allocate(systemInfo);
            getSystemInfo.invoke(info);
            long size = Integer.toUnsignedLong(info.get(ValueLayout.JAVA_INT, pageSizeOffset));
            if (size <= 0L || (size & (size - 1L)) != 0L) {
                throw new NativeMemoryUnavailableException(
                        NativePlatform.WINDOWS_X86_64, NativeMemoryOperation.PLATFORM);
            }
            return size;
        } catch (Throwable t) {
            throw FfmSupport.rethrow(t);
        }
    }
}
