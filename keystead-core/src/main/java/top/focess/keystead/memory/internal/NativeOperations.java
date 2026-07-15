package top.focess.keystead.memory.internal;

import java.lang.foreign.MemorySegment;
import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.NativePlatform;

/**
 * Internal native-operation boundary used by ownership code and deterministic fakes.
 *
 * <p>Pointer operations ({@link #allocate}, {@link #lock}, {@link #dumpExclude}, {@link #unlock},
 * {@link #release}) are address based so that the owner-free cleaner state can clean up an abandoned
 * mapping without retaining a live segment reference. Content operations ({@link #copyIn},
 * {@link #wipe}) receive the owner-held {@link MemorySegment}; segments never escape the provider
 * implementation.
 */
interface NativeOperations {

    @NonNull NativePlatform platform();

    long pageSize();

    @NonNull NativeOperationResult allocate(long byteSize);

    @NonNull NativeOperationResult lock(long address, long byteSize);

    @NonNull NativeOperationResult dumpExclude(long address, long byteSize);

    @NonNull NativeOperationResult copyIn(@NonNull MemorySegment segment, byte @NonNull [] value);

    @NonNull NativeOperationResult wipe(@NonNull MemorySegment segment, long byteSize);

    @NonNull NativeOperationResult unlock(long address, long byteSize);

    @NonNull NativeOperationResult release(long address, long byteSize);
}
