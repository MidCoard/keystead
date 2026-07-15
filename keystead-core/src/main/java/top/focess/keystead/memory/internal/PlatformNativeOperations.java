package top.focess.keystead.memory.internal;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.VarHandle;
import java.util.Objects;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.NativePlatform;

/** Common sentinel and policy checks around platform-specific native invocations. */
abstract class PlatformNativeOperations implements NativeOperations {

    private static final long POSIX_MAP_FAILED = -1L;

    private static final @NonNull VarHandle BYTE = ValueLayout.JAVA_BYTE.varHandle();

    private final @NonNull NativePlatform platform;

    PlatformNativeOperations(@NonNull NativePlatform platform) {
        this.platform = Objects.requireNonNull(platform, "platform");
        if (platform == NativePlatform.UNSUPPORTED) {
            throw new IllegalArgumentException("Unsupported platform has no native operations");
        }
    }

    @Override
    public final @NonNull NativeOperationResult allocate(long byteSize) {
        requirePositiveSize(byteSize);
        NativeCallResult result = allocateNative(byteSize);
        long address = result.returnValue();
        if (platform == NativePlatform.WINDOWS_X86_64) {
            if (address == 0L) {
                return NativeOperationResult.operationFailed(result.capturedErrorCode());
            }
            return NativeOperationResult.success(address);
        }
        if (address == POSIX_MAP_FAILED) {
            return NativeOperationResult.operationFailed(result.capturedErrorCode());
        }
        if (address == 0L) {
            release(0L, byteSize);
            return NativeOperationResult.zeroAddressRejected();
        }
        return NativeOperationResult.success(address);
    }

    @Override
    public final @NonNull NativeOperationResult lock(long address, long byteSize) {
        requirePositiveSize(byteSize);
        return toResult(lockNative(address, byteSize));
    }

    @Override
    public final @NonNull NativeOperationResult dumpExclude(long address, long byteSize) {
        requirePositiveSize(byteSize);
        return toResult(dumpExcludeNative(address, byteSize));
    }

    @Override
    public final @NonNull NativeOperationResult unlock(long address, long byteSize) {
        requirePositiveSize(byteSize);
        return toResult(unlockNative(address, byteSize));
    }

    @Override
    public final @NonNull NativeOperationResult release(long address, long byteSize) {
        requirePositiveSize(byteSize);
        return toResult(releaseNative(address, byteSize));
    }

    private @NonNull NativeOperationResult toResult(@NonNull NativeCallResult result) {
        boolean successful =
                platform == NativePlatform.WINDOWS_X86_64
                        ? result.returnValue() != 0L
                        : result.returnValue() == 0L;
        return successful
                ? NativeOperationResult.success(result.returnValue())
                : NativeOperationResult.operationFailed(result.capturedErrorCode());
    }

    protected abstract @NonNull NativeCallResult allocateNative(long byteSize);

    protected abstract @NonNull NativeCallResult lockNative(long address, long byteSize);

    protected abstract @NonNull NativeCallResult dumpExcludeNative(long address, long byteSize);

    protected abstract @NonNull NativeCallResult unlockNative(long address, long byteSize);

    protected abstract @NonNull NativeCallResult releaseNative(long address, long byteSize);

    @Override
    public @NonNull NativeOperationResult copyIn(
            @NonNull MemorySegment segment, byte @NonNull [] value) {
        MemorySegment source = MemorySegment.ofArray(value);
        segment.asSlice(0, value.length).copyFrom(source);
        return NativeOperationResult.success(0L);
    }

    @Override
    public @NonNull NativeOperationResult wipe(@NonNull MemorySegment segment, long byteSize) {
        for (long offset = 0L; offset < byteSize; offset++) {
            BYTE.setVolatile(segment, offset, (byte) 0);
        }
        VarHandle.fullFence();
        return NativeOperationResult.success(0L);
    }

    @Override
    public final @NonNull NativePlatform platform() {
        return platform;
    }

    private static void requirePositiveSize(long byteSize) {
        if (byteSize <= 0L) {
            throw new IllegalArgumentException("Native operation size must be positive");
        }
    }

    protected record NativeCallResult(long returnValue, long capturedErrorCode) {

        protected NativeCallResult {
            if (capturedErrorCode < 0L) {
                throw new IllegalArgumentException("Captured OS error code must not be negative");
            }
        }
    }
}
