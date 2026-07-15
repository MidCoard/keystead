package top.focess.keystead.memory.internal;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.NativePlatform;

final class FakeNativeOperations extends PlatformNativeOperations {

    private final long allocationReturnValue;
    private final long allocationErrorCode;
    private final long releaseReturnValue;
    private final long releaseErrorCode;
    private final @NonNull List<@NonNull ReleaseCall> releaseCalls = new ArrayList<>();

    private FakeNativeOperations(
            @NonNull NativePlatform platform,
            long allocationReturnValue,
            long allocationErrorCode,
            long releaseReturnValue,
            long releaseErrorCode) {
        super(platform);
        this.allocationReturnValue = allocationReturnValue;
        this.allocationErrorCode = allocationErrorCode;
        this.releaseReturnValue = releaseReturnValue;
        this.releaseErrorCode = releaseErrorCode;
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
                Integer.toUnsignedLong(releaseLastError));
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
                releaseErrno);
    }

    @Override
    protected @NonNull NativeCallResult allocateNative(long byteSize) {
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

    record ReleaseCall(long address, long byteSize) {}
}
