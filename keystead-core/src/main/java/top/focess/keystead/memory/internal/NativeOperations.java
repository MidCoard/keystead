package top.focess.keystead.memory.internal;

import org.jspecify.annotations.NonNull;
import top.focess.keystead.memory.NativePlatform;

/** Internal native-operation boundary used by ownership code and deterministic fakes. */
interface NativeOperations {

    @NonNull NativePlatform platform();

    long pageSize();

    @NonNull NativeOperationResult allocate(long byteSize);

    @NonNull NativeOperationResult release(long address, long byteSize);
}
