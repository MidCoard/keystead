package top.focess.keystead.memory.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import top.focess.keystead.memory.NativeMemoryOperation;
import top.focess.keystead.memory.NativeMemoryUnavailableException;
import top.focess.keystead.memory.NativePlatform;

class NativeSecretMemoryTest {

    @Test
    void allocationFailureDoesNotAttemptCleanupForAnUnownedMapping() {
        FakeNativeOperations operations =
                FakeNativeOperations.lifecycle(NativePlatform.LINUX_X86_64, 4096L)
                        .fail(NativeMemoryOperation.ALLOCATION, 12L);

        NativeMemoryUnavailableException failure =
                assertThrows(
                        NativeMemoryUnavailableException.class,
                        () -> NativeSecretMemory.allocate(new byte[] {1, 2, 3}, operations));

        assertEquals(NativeMemoryOperation.ALLOCATION, failure.operation());
        assertEquals(12L, failure.osErrorCode());
        assertEquals(java.util.List.of("allocate"), operations.calls());
    }
}
