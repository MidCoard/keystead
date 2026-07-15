package top.focess.keystead.memory.internal;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.memory.NativeMemoryOperation;
import top.focess.keystead.memory.NativePlatform;

/**
 * Deterministic fake {@link NativeOperations} for ownership and cleanup tests.
 *
 * <p>The {@link #lifecycle(NativePlatform, long)} mode backs a successful allocation with a real
 * off-heap segment so the owner can reinterpret the returned address, copy bytes in, and wipe it;
 * the fake retains that backing for post-cleanup inspection. Every lifecycle stage can be made to
 * fail once via {@link #fail(NativeMemoryOperation, long)}. The {@link #posix(long, int, long, int)}
 * and {@link #windows(long, int, long, int)} factories remain pure-simulation for ABI-result tests.
 */
final class FakeNativeOperations extends PlatformNativeOperations implements AutoCloseable {

    private final boolean lifecycleMode;
    private final long pageSize;

    private final long syntheticAllocationReturn;
    private final long syntheticAllocationError;
    private final long syntheticReleaseReturn;
    private final long syntheticReleaseError;

    private final @Nullable Arena backingArena;
    private @Nullable MemorySegment backing;
    private long allocatedAddress;

    private final @NonNull Map<@NonNull NativeMemoryOperation, @NonNull Long> failErrorCodes =
            new EnumMap<>(NativeMemoryOperation.class);

    private final @NonNull List<@NonNull String> calls = new ArrayList<>();
    private final @NonNull List<@NonNull ReleaseCall> releaseCalls = new ArrayList<>();
    private final @NonNull List<@NonNull Long> wipeByteSizes = new ArrayList<>();
    private boolean fenceRecorded;

    private FakeNativeOperations(
            @NonNull NativePlatform platform,
            boolean lifecycleMode,
            long pageSize,
            long syntheticAllocationReturn,
            long syntheticAllocationError,
            long syntheticReleaseReturn,
            long syntheticReleaseError) {
        super(platform);
        this.lifecycleMode = lifecycleMode;
        this.pageSize = pageSize;
        this.syntheticAllocationReturn = syntheticAllocationReturn;
        this.syntheticAllocationError = syntheticAllocationError;
        this.syntheticReleaseReturn = syntheticReleaseReturn;
        this.syntheticReleaseError = syntheticReleaseError;
        this.backingArena = lifecycleMode ? Arena.ofShared() : null;
    }

    static @NonNull FakeNativeOperations lifecycle(
            @NonNull NativePlatform platform, long pageSize) {
        if (pageSize <= 0L) {
            throw new IllegalArgumentException("Page size must be positive");
        }
        return new FakeNativeOperations(platform, true, pageSize, 0L, 0L, 0L, 0L);
    }

    static @NonNull FakeNativeOperations windows(
            long allocationReturnValue,
            int allocationLastError,
            long releaseReturnValue,
            int releaseLastError) {
        return new FakeNativeOperations(
                NativePlatform.WINDOWS_X86_64,
                false,
                4096L,
                allocationReturnValue,
                Integer.toUnsignedLong(allocationLastError),
                releaseReturnValue,
                Integer.toUnsignedLong(releaseLastError));
    }

    static @NonNull FakeNativeOperations posix(
            long allocationReturnValue,
            int allocationErrno,
            long releaseReturnValue,
            int releaseErrno) {
        return new FakeNativeOperations(
                NativePlatform.LINUX_X86_64,
                false,
                4096L,
                allocationReturnValue,
                Integer.toUnsignedLong(allocationErrno),
                releaseReturnValue,
                Integer.toUnsignedLong(releaseErrno));
    }

    @NonNull FakeNativeOperations fail(@NonNull NativeMemoryOperation operation, long errorCode) {
        if (errorCode < 0L) {
            throw new IllegalArgumentException("Error code must not be negative");
        }
        failErrorCodes.put(operation, errorCode);
        return this;
    }

    @Override
    public long pageSize() {
        return pageSize;
    }

    @Override
    protected @NonNull NativeCallResult allocateNative(long byteSize) {
        calls.add("allocate");
        if (!lifecycleMode) {
            return new NativeCallResult(syntheticAllocationReturn, syntheticAllocationError);
        }
        Long failCode = failErrorCodes.remove(NativeMemoryOperation.ALLOCATION);
        if (failCode != null) {
            return new NativeCallResult(posixFailureSentinel(), failCode);
        }
        this.backing = backingArena.allocate(byteSize);
        this.allocatedAddress = backing.address();
        return new NativeCallResult(allocatedAddress, 0L);
    }

    @Override
    protected @NonNull NativeCallResult lockNative(long address, long byteSize) {
        calls.add("lock");
        return failOrSuccess(NativeMemoryOperation.PAGE_LOCK);
    }

    @Override
    protected @NonNull NativeCallResult dumpExcludeNative(long address, long byteSize) {
        calls.add("dumpExclude");
        return failOrSuccess(NativeMemoryOperation.DUMP_EXCLUSION);
    }

    @Override
    protected @NonNull NativeCallResult unlockNative(long address, long byteSize) {
        calls.add("unlock");
        return failOrSuccess(NativeMemoryOperation.PAGE_UNLOCK);
    }

    @Override
    protected @NonNull NativeCallResult releaseNative(long address, long byteSize) {
        calls.add("release");
        releaseCalls.add(new ReleaseCall(address, byteSize));
        if (!lifecycleMode) {
            return new NativeCallResult(syntheticReleaseReturn, syntheticReleaseError);
        }
        return failOrSuccess(NativeMemoryOperation.RELEASE);
    }

    @Override
    public @NonNull NativeOperationResult copyIn(
            @NonNull MemorySegment segment, byte @NonNull [] value) {
        calls.add("copyIn");
        Long failCode = failErrorCodes.remove(NativeMemoryOperation.COPY);
        int toWrite = failCode != null ? Math.max(0, value.length / 2) : value.length;
        if (toWrite > 0) {
            MemorySegment source = MemorySegment.ofArray(value);
            segment.asSlice(0, toWrite).copyFrom(source.asSlice(0, toWrite));
        }
        if (failCode != null) {
            return NativeOperationResult.operationFailed(failCode);
        }
        return NativeOperationResult.success(0L);
    }

    @Override
    public @NonNull NativeOperationResult wipe(@NonNull MemorySegment segment, long byteSize) {
        calls.add("wipe");
        wipeByteSizes.add(byteSize);
        Long failCode = failErrorCodes.remove(NativeMemoryOperation.WIPE);
        if (failCode == null) {
            for (long offset = 0L; offset < byteSize; offset++) {
                segment.set(ValueLayout.JAVA_BYTE, offset, (byte) 0);
            }
        }
        fenceRecorded = true;
        if (failCode != null) {
            return NativeOperationResult.operationFailed(failCode);
        }
        return NativeOperationResult.success(0L);
    }

    private @NonNull NativeCallResult failOrSuccess(@NonNull NativeMemoryOperation operation) {
        Long failCode = failErrorCodes.remove(operation);
        if (failCode != null) {
            return new NativeCallResult(posixFailureSentinel(), failCode);
        }
        return new NativeCallResult(successReturn(), 0L);
    }

    private long posixFailureSentinel() {
        return platform() == NativePlatform.WINDOWS_X86_64 ? 0L : -1L;
    }

    private long successReturn() {
        return platform() == NativePlatform.WINDOWS_X86_64 ? 1L : 0L;
    }

    @NonNull List<@NonNull String> calls() {
        return Collections.unmodifiableList(calls);
    }

    @NonNull List<@NonNull ReleaseCall> releaseCalls() {
        return Collections.unmodifiableList(releaseCalls);
    }

    @NonNull List<@NonNull Long> wipeByteSizes() {
        return Collections.unmodifiableList(wipeByteSizes);
    }

    boolean fenceRecorded() {
        return fenceRecorded;
    }

    long allocatedAddress() {
        return allocatedAddress;
    }

    @Nullable MemorySegment backing() {
        return backing;
    }

    @Override
    public void close() {
        if (backingArena != null) {
            backingArena.close();
        }
    }

    record ReleaseCall(long address, long byteSize) {}
}
