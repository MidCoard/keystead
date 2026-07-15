package top.focess.keystead.memory.internal;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.NativeMemoryOperation;
import top.focess.keystead.memory.NativePlatform;

final class FakeNativeOperations extends PlatformNativeOperations {

    private long allocationReturnValue;
    private long allocationErrorCode;
    private final long releaseReturnValue;
    private final long releaseErrorCode;
    private final @NonNull List<@NonNull ReleaseCall> releaseCalls = new ArrayList<>();
    private final @NonNull List<@NonNull String> calls = new ArrayList<>();
    private final long pageSize;

    private FakeNativeOperations(
            @NonNull NativePlatform platform,
            long allocationReturnValue,
            long allocationErrorCode,
            long releaseReturnValue,
            long releaseErrorCode,
            long pageSize) {
        super(platform);
        this.allocationReturnValue = allocationReturnValue;
        this.allocationErrorCode = allocationErrorCode;
        this.releaseReturnValue = releaseReturnValue;
        this.releaseErrorCode = releaseErrorCode;
        this.pageSize = pageSize;
    }

    static @NonNull FakeNativeOperations lifecycle(
            @NonNull NativePlatform platform, long pageSize) {
        if (pageSize <= 0L) {
            throw new IllegalArgumentException("Page size must be positive");
        }
        return new FakeNativeOperations(platform, 4096L, 0L, 0L, 0L, pageSize);
    }

    @NonNull FakeNativeOperations fail(@NonNull NativeMemoryOperation operation, long errorCode) {
        if (operation != NativeMemoryOperation.ALLOCATION) {
            throw new IllegalArgumentException("Unsupported fake failure operation");
        }
        allocationReturnValue = platform() == NativePlatform.WINDOWS_X86_64 ? 0L : -1L;
        allocationErrorCode = errorCode;
        return this;
    }

    @Override
    public long pageSize() {
        return pageSize;
    }

    static @NonNull FakeNativeOperations windows(
            long allocationReturnValue,
            int allocationLastError,
            long releaseReturnValue,
            int releaseLastError) {
        return new FakeNativeOperations(
                NativePlatform.WINDOWS_X86_64,
                allocationReturnValue,
                Integer.toUnsignedLong(allocationLastError),
                releaseReturnValue,
                Integer.toUnsignedLong(releaseLastError),
                4096L);
    }

    static @NonNull FakeNativeOperations posix(
            long allocationReturnValue,
            int allocationErrno,
            long releaseReturnValue,
            int releaseErrno) {
        return new FakeNativeOperations(
                NativePlatform.LINUX_X86_64,
                allocationReturnValue,
                allocationErrno,
                releaseReturnValue,
                releaseErrno,
                4096L);
    }

    @Override
    protected @NonNull NativeCallResult allocateNative(long byteSize) {
        calls.add("allocate");
        return new NativeCallResult(allocationReturnValue, allocationErrorCode);
    }

    @Override
    protected @NonNull NativeCallResult releaseNative(long address, long byteSize) {
        releaseCalls.add(new ReleaseCall(address, byteSize));
        return new NativeCallResult(releaseReturnValue, releaseErrorCode);
    }

    @NonNull List<@NonNull ReleaseCall> releaseCalls() {
        return Collections.unmodifiableList(releaseCalls);
    }

    @NonNull List<@NonNull String> calls() {
        return Collections.unmodifiableList(calls);
    }

    record ReleaseCall(long address, long byteSize) {}
}
