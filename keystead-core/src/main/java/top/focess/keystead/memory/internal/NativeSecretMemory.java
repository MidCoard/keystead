package top.focess.keystead.memory.internal;

import java.util.Objects;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import top.focess.keystead.memory.NativeMemoryOperation;
import top.focess.keystead.memory.NativeMemoryUnavailableException;

/** Allocation stage for one independently protected native secret mapping. */
final class NativeSecretMemory {

    private NativeSecretMemory() {}

    static long allocate(byte @NonNull [] value, @NonNull NativeOperations operations) {
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(operations, "operations");
        long byteSize = NativeAbi.roundToPage(value.length, operations.pageSize());
        NativeOperationResult result = operations.allocate(byteSize);
        if (!result.successful()) {
            @Nullable Long errorCode = result.osErrorCode();
            if (errorCode == null) {
                throw new NativeMemoryUnavailableException(
                        operations.platform(), NativeMemoryOperation.ALLOCATION);
            }
            throw new NativeMemoryUnavailableException(
                    operations.platform(), NativeMemoryOperation.ALLOCATION, errorCode);
        }
        return result.value();
    }
}
