package top.focess.keystead.memory.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.lang.foreign.ValueLayout;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import top.focess.keystead.memory.NativeMemoryOperation;
import top.focess.keystead.memory.NativeMemoryUnavailableException;
import top.focess.keystead.memory.NativePlatform;
import top.focess.keystead.memory.SecretDestroyedException;

class NativeSecretMemoryTest {

    @Test
    void allocationFailureDoesNotAttemptCleanupForAnUnownedMapping() {
        FakeNativeOperations operations =
                FakeNativeOperations.lifecycle(NativePlatform.LINUX_X86_64, 4096L)
                        .fail(NativeMemoryOperation.ALLOCATION, 12L);

        NativeMemoryUnavailableException failure =
                assertThrows(
                        NativeMemoryUnavailableException.class,
                        () -> NativeSecretMemory.create(new byte[] {1, 2, 3}, operations));

        assertEquals(NativeMemoryOperation.ALLOCATION, failure.operation());
        assertEquals(12L, failure.osErrorCode());
        assertEquals(List.of("allocate"), operations.calls());
        assertTrue(operations.releaseCalls().isEmpty());
    }

    @Test
    void linuxConstructionAdvancesThroughDumpExclusionToLiveAndCopiesBytes() {
        FakeNativeOperations operations =
                FakeNativeOperations.lifecycle(NativePlatform.LINUX_X86_64, 4096L);
        try (FakeNativeOperations fake = operations;
                NativeSecretMemory memory = NativeSecretMemory.create(new byte[] {1, 2, 3}, fake)) {
            assertEquals(3, memory.length());
            assertFalse(memory.isClosed());
            assertEquals(List.of("allocate", "lock", "dumpExclude", "copyIn"), fake.calls());
            assertBackingEquals(fake, new byte[] {1, 2, 3});

            memory.copyBytes(bytes -> assertArrayEquals(new byte[] {1, 2, 3}, bytes));
        }
    }

    @Test
    void windowsConstructionOmitsDumpExclusion() {
        FakeNativeOperations operations =
                FakeNativeOperations.lifecycle(NativePlatform.WINDOWS_X86_64, 4096L);
        try (FakeNativeOperations fake = operations;
                NativeSecretMemory memory = NativeSecretMemory.create(new byte[] {42}, fake)) {
            assertEquals(1, memory.length());
            assertEquals(List.of("allocate", "lock", "copyIn"), fake.calls());
        }
    }

    @Test
    void macosConstructionOmitsDumpExclusion() {
        FakeNativeOperations operations =
                FakeNativeOperations.lifecycle(NativePlatform.MACOS_AARCH64, 4096L);
        try (FakeNativeOperations fake = operations;
                NativeSecretMemory memory = NativeSecretMemory.create(new byte[] {7, 8}, fake)) {
            assertEquals(2, memory.length());
            assertEquals(List.of("allocate", "lock", "copyIn"), fake.calls());
        }
    }

    @Test
    void lockFailureReleasesTheAllocatedMappingWithoutWipingOrUnlocking() {
        FakeNativeOperations operations =
                FakeNativeOperations.lifecycle(NativePlatform.LINUX_X86_64, 4096L)
                        .fail(NativeMemoryOperation.PAGE_LOCK, 1L);

        NativeMemoryUnavailableException failure =
                assertThrows(
                        NativeMemoryUnavailableException.class,
                        () -> NativeSecretMemory.create(new byte[] {1, 2, 3}, operations));

        assertEquals(NativeMemoryOperation.PAGE_LOCK, failure.operation());
        assertEquals(1L, failure.osErrorCode());
        assertEquals(List.of("allocate", "lock", "release"), operations.calls());
        assertTrue(operations.wipeByteSizes().isEmpty());
    }

    @Test
    void dumpExclusionFailureUnlocksAndReleasesWithoutWiping() {
        FakeNativeOperations operations =
                FakeNativeOperations.lifecycle(NativePlatform.LINUX_X86_64, 4096L)
                        .fail(NativeMemoryOperation.DUMP_EXCLUSION, 2L);

        NativeMemoryUnavailableException failure =
                assertThrows(
                        NativeMemoryUnavailableException.class,
                        () -> NativeSecretMemory.create(new byte[] {1, 2, 3}, operations));

        assertEquals(NativeMemoryOperation.DUMP_EXCLUSION, failure.operation());
        assertEquals(
                List.of("allocate", "lock", "dumpExclude", "unlock", "release"),
                operations.calls());
        assertTrue(operations.wipeByteSizes().isEmpty());
    }

    @Test
    void copyFailureWipesTheFullMappingThenUnlocksAndReleases() {
        FakeNativeOperations operations =
                FakeNativeOperations.lifecycle(NativePlatform.LINUX_X86_64, 4096L)
                        .fail(NativeMemoryOperation.COPY, 5L);

        NativeMemoryUnavailableException failure =
                assertThrows(
                        NativeMemoryUnavailableException.class,
                        () -> NativeSecretMemory.create(new byte[] {1, 2, 3, 4, 5}, operations));

        assertEquals(NativeMemoryOperation.COPY, failure.operation());
        assertEquals(
                List.of("allocate", "lock", "dumpExclude", "copyIn", "wipe", "unlock", "release"),
                operations.calls());
        assertEquals(List.of(4096L), operations.wipeByteSizes());
    }

    @Test
    void closeWipesTheFullMappingBeforeUnlockAndRelease() {
        FakeNativeOperations operations =
                FakeNativeOperations.lifecycle(NativePlatform.LINUX_X86_64, 4096L);
        try (FakeNativeOperations fake = operations) {
            NativeSecretMemory memory = NativeSecretMemory.create(new byte[] {9, 9, 9}, fake);
            assertBackingEquals(fake, new byte[] {9, 9, 9});

            memory.close();

            assertEquals(
                    List.of(
                            "allocate",
                            "lock",
                            "dumpExclude",
                            "copyIn",
                            "wipe",
                            "unlock",
                            "release"),
                    fake.calls());
            assertEquals(List.of(4096L), fake.wipeByteSizes());
            assertTrue(fake.fenceRecorded());
            assertBackingAllZero(fake, 4096L);
            assertTrue(memory.isClosed());
        }
    }

    @Test
    void closeContinuesUnlockAndReleaseAfterInjectedWipeFailure() {
        FakeNativeOperations operations =
                FakeNativeOperations.lifecycle(NativePlatform.LINUX_X86_64, 4096L)
                        .fail(NativeMemoryOperation.WIPE, 7L);
        try (FakeNativeOperations fake = operations) {
            NativeSecretMemory memory = NativeSecretMemory.create(new byte[] {1, 2, 3}, fake);

            NativeMemoryUnavailableException failure =
                    assertThrows(NativeMemoryUnavailableException.class, memory::close);

            assertEquals(NativeMemoryOperation.WIPE, failure.operation());
            assertEquals(7L, failure.osErrorCode());
            assertTrue(
                    fake.calls().containsAll(List.of("wipe", "unlock", "release")),
                    "cleanup must attempt unlock and release after wipe failure");
        }
    }

    @Test
    void closeContinuesReleaseAfterInjectedUnlockFailure() {
        FakeNativeOperations operations =
                FakeNativeOperations.lifecycle(NativePlatform.LINUX_X86_64, 4096L)
                        .fail(NativeMemoryOperation.PAGE_UNLOCK, 8L);
        try (FakeNativeOperations fake = operations) {
            NativeSecretMemory memory = NativeSecretMemory.create(new byte[] {1, 2, 3}, fake);

            NativeMemoryUnavailableException failure =
                    assertThrows(NativeMemoryUnavailableException.class, memory::close);

            assertEquals(NativeMemoryOperation.PAGE_UNLOCK, failure.operation());
            assertTrue(fake.calls().contains("release"));
        }
    }

    @Test
    void multipleCleanupFailuresThrowTheFirstAndSuppressTheRestRedacted() {
        FakeNativeOperations operations =
                FakeNativeOperations.lifecycle(NativePlatform.LINUX_X86_64, 4096L)
                        .fail(NativeMemoryOperation.WIPE, 1L)
                        .fail(NativeMemoryOperation.PAGE_UNLOCK, 2L)
                        .fail(NativeMemoryOperation.RELEASE, 3L);
        try (FakeNativeOperations fake = operations) {
            NativeSecretMemory memory =
                    NativeSecretMemory.create(new byte[] {(byte) 0xFE, (byte) 0xED}, fake);

            NativeMemoryUnavailableException failure =
                    assertThrows(NativeMemoryUnavailableException.class, memory::close);

            assertEquals(NativeMemoryOperation.WIPE, failure.operation());
            assertEquals(2, failure.getSuppressed().length);
            assertNull(failure.getCause());

            StringBuilder graph = new StringBuilder();
            graph.append(failure.getMessage()).append(failure.toString());
            for (Throwable suppressed : failure.getSuppressed()) {
                assertInstanceOf(NativeMemoryUnavailableException.class, suppressed);
                assertNull(suppressed.getCause());
                graph.append(suppressed.getMessage()).append(suppressed.toString());
            }
            String rendered = graph.toString();
            assertFalse(
                    rendered.contains(Long.toString(fake.allocatedAddress())),
                    "redacted graph must not contain the native address");
            assertFalse(
                    rendered.contains("254") || rendered.contains("237"),
                    "redacted graph must not contain secret bytes");
        }
    }

    @Test
    void constructionFailureSuppressesCleanupFailuresUnderTheConstructionError() {
        FakeNativeOperations operations =
                FakeNativeOperations.lifecycle(NativePlatform.LINUX_X86_64, 4096L)
                        .fail(NativeMemoryOperation.COPY, 5L)
                        .fail(NativeMemoryOperation.WIPE, 6L)
                        .fail(NativeMemoryOperation.RELEASE, 9L);

        NativeMemoryUnavailableException failure =
                assertThrows(
                        NativeMemoryUnavailableException.class,
                        () -> NativeSecretMemory.create(new byte[] {1, 2, 3}, operations));

        assertEquals(NativeMemoryOperation.COPY, failure.operation());
        assertEquals(5L, failure.osErrorCode());
        assertTrue(failure.getSuppressed().length >= 1);
    }

    @Test
    void copyBytesWipesTheTemporaryHeapCopyAfterTheConsumerReturns() {
        FakeNativeOperations operations =
                FakeNativeOperations.lifecycle(NativePlatform.LINUX_X86_64, 4096L);
        try (FakeNativeOperations fake = operations;
                NativeSecretMemory memory = NativeSecretMemory.create(new byte[] {1, 2, 3}, fake)) {
            AtomicReference<byte[]> captured = new AtomicReference<>();

            memory.copyBytes(
                    bytes -> {
                        assertArrayEquals(new byte[] {1, 2, 3}, bytes);
                        captured.set(bytes);
                    });

            assertArrayEquals(new byte[3], captured.get());
        }
    }

    @Test
    void copyBytesWipesTheTemporaryHeapCopyWhenTheConsumerThrows() {
        FakeNativeOperations operations =
                FakeNativeOperations.lifecycle(NativePlatform.LINUX_X86_64, 4096L);
        try (FakeNativeOperations fake = operations;
                NativeSecretMemory memory = NativeSecretMemory.create(new byte[] {1, 2, 3}, fake)) {
            AtomicReference<byte[]> captured = new AtomicReference<>();

            assertThrows(
                    IllegalStateException.class,
                    () ->
                            memory.copyBytes(
                                    bytes -> {
                                        captured.set(bytes);
                                        throw new IllegalStateException("failed");
                                    }));

            assertArrayEquals(new byte[3], captured.get());
        }
    }

    @Test
    void repeatedCloseIsANoOpAfterCleanup() {
        FakeNativeOperations operations =
                FakeNativeOperations.lifecycle(NativePlatform.LINUX_X86_64, 4096L);
        try (FakeNativeOperations fake = operations) {
            NativeSecretMemory memory = NativeSecretMemory.create(new byte[] {1, 2, 3}, fake);

            memory.close();
            int releaseCount = fake.releaseCalls().size();
            memory.close();
            memory.close();

            assertEquals(releaseCount, fake.releaseCalls().size());
            assertTrue(memory.isClosed());
        }
    }

    @Test
    void accessAfterCloseFailsClosedWithoutReopening() {
        FakeNativeOperations operations =
                FakeNativeOperations.lifecycle(NativePlatform.LINUX_X86_64, 4096L)
                        .fail(NativeMemoryOperation.RELEASE, 4L);
        try (FakeNativeOperations fake = operations) {
            NativeSecretMemory memory = NativeSecretMemory.create(new byte[] {1, 2, 3}, fake);

            assertThrows(NativeMemoryUnavailableException.class, memory::close);
            assertTrue(memory.isClosed());
            assertThrows(SecretDestroyedException.class, memory::length);
            assertThrows(SecretDestroyedException.class, () -> memory.copyBytes(bytes -> fail()));
        }
    }

    @Test
    void nestedCopyInvokesTheConsumerForEachLevel() {
        FakeNativeOperations operations =
                FakeNativeOperations.lifecycle(NativePlatform.LINUX_X86_64, 4096L);
        try (FakeNativeOperations fake = operations;
                NativeSecretMemory memory = NativeSecretMemory.create(new byte[] {1, 2, 3}, fake)) {
            int[] count = {0};

            memory.copyBytes(
                    outer ->
                            memory.copyBytes(
                                    inner -> {
                                        assertArrayEquals(new byte[] {1, 2, 3}, outer);
                                        assertArrayEquals(new byte[] {1, 2, 3}, inner);
                                        count[0]++;
                                    }));

            assertEquals(1, count[0]);
            assertFalse(memory.isClosed());
        }
    }

    @Test
    void closeFromWithinACallbackDefersCleanupUntilTheOutermostCallbackExits() {
        FakeNativeOperations operations =
                FakeNativeOperations.lifecycle(NativePlatform.LINUX_X86_64, 4096L);
        try (FakeNativeOperations fake = operations) {
            NativeSecretMemory memory = NativeSecretMemory.create(new byte[] {1, 2, 3}, fake);

            memory.copyBytes(
                    bytes -> {
                        assertArrayEquals(new byte[] {1, 2, 3}, bytes);
                        memory.close();
                        assertTrue(memory.isClosed());
                        // nested access after the close request fails
                        assertThrows(
                                SecretDestroyedException.class, () -> memory.copyBytes(b -> {}));
                    });

            // cleanup deferred until the outermost callback exited
            assertEquals(1, fake.releaseCalls().size());
        }
    }

    @Test
    void crossThreadCloseWaitsForAnInFlightCallback() throws Exception {
        FakeNativeOperations operations =
                FakeNativeOperations.lifecycle(NativePlatform.LINUX_X86_64, 4096L);
        try (FakeNativeOperations fake = operations) {
            NativeSecretMemory memory = NativeSecretMemory.create(new byte[] {1, 2, 3}, fake);
            CountDownLatch entered = new CountDownLatch(1);
            CountDownLatch release = new CountDownLatch(1);
            CountDownLatch closeStarted = new CountDownLatch(1);
            ExecutorService executor = Executors.newFixedThreadPool(2);
            try {
                Future<?> access =
                        executor.submit(
                                () ->
                                        memory.copyBytes(
                                                bytes -> {
                                                    entered.countDown();
                                                    await(release);
                                                    assertArrayEquals(new byte[] {1, 2, 3}, bytes);
                                                }));
                assertTrue(entered.await(2, TimeUnit.SECONDS));

                Future<?> close =
                        executor.submit(
                                () -> {
                                    closeStarted.countDown();
                                    memory.close();
                                });
                assertTrue(closeStarted.await(2, TimeUnit.SECONDS));
                assertThrows(TimeoutException.class, () -> close.get(100, TimeUnit.MILLISECONDS));

                release.countDown();
                access.get(2, TimeUnit.SECONDS);
                close.get(2, TimeUnit.SECONDS);
                assertTrue(memory.isClosed());
            } finally {
                release.countDown();
                memory.close();
                executor.shutdownNow();
            }
        }
    }

    @Test
    void abandonedOwnerIsCleanedUpByTheCleaner() throws Exception {
        FakeNativeOperations fake =
                FakeNativeOperations.lifecycle(NativePlatform.LINUX_X86_64, 4096L);
        NativeSecretMemory memory = NativeSecretMemory.create(new byte[] {1, 2, 3}, fake);
        java.lang.ref.WeakReference<NativeSecretMemory> reference =
                new java.lang.ref.WeakReference<>(memory);
        memory = null;

        boolean cleaned = false;
        for (int i = 0; i < 40; i++) {
            System.gc();
            Thread.sleep(50L);
            if (!fake.releaseCalls().isEmpty()) {
                cleaned = true;
                break;
            }
        }
        assertTrue(reference.get() == null || cleaned, "owner must become unreachable");
        assertTrue(cleaned, "Cleaner must perform one-pass cleanup for an abandoned owner");
        fake.close();
    }

    @Test
    void zeroLengthSecretOwnsOneProtectedPage() {
        FakeNativeOperations operations =
                FakeNativeOperations.lifecycle(NativePlatform.LINUX_X86_64, 4096L);
        try (FakeNativeOperations fake = operations) {
            NativeSecretMemory memory = NativeSecretMemory.create(new byte[0], fake);

            assertEquals(0, memory.length());
            memory.copyBytes(bytes -> assertEquals(0, bytes.length));

            memory.close();
            assertEquals(List.of(4096L), fake.wipeByteSizes());
        }
    }

    private static void assertBackingEquals(FakeNativeOperations fake, byte[] expected) {
        assertNotNull(fake.backing());
        for (int i = 0; i < expected.length; i++) {
            assertEquals(expected[i], fake.backing().get(ValueLayout.JAVA_BYTE, i), "byte " + i);
        }
    }

    private static void assertBackingAllZero(FakeNativeOperations fake, long byteSize) {
        assertNotNull(fake.backing());
        for (long i = 0; i < byteSize; i++) {
            assertEquals(0, fake.backing().get(ValueLayout.JAVA_BYTE, i), "byte " + i);
        }
    }

    private static void assertArrayEquals(byte[] expected, byte[] actual) {
        org.junit.jupiter.api.Assertions.assertArrayEquals(expected, actual);
    }

    private static void await(CountDownLatch latch) {
        try {
            assertTrue(latch.await(2, TimeUnit.SECONDS));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AssertionError(e);
        }
    }
}
