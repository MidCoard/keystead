package top.focess.keystead.memory;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class SecretMemoryProviderTest {

    @Test
    void heapMemoryReportsLifecycleAndRejectsLengthAfterClose() {
        SecretMemory memory = SecretMemoryProvider.heap().protect(new byte[] {1, 2, 3});

        assertEquals(3, memory.length());
        assertFalse(memory.isClosed());

        memory.close();

        assertTrue(memory.isClosed());
        assertThrows(SecretDestroyedException.class, memory::length);
    }

    @Test
    void heapProviderCopiesCallerOwnedInputAndWipesCallbackCopy() {
        byte[] input = new byte[] {1, 2, 3};
        AtomicReference<byte[]> callbackCopy = new AtomicReference<>();

        try (SecretMemory memory = SecretMemoryProvider.heap().protect(input)) {
            Arrays.fill(input, (byte) 0);
            memory.copyBytes(
                    bytes -> {
                        callbackCopy.set(bytes);
                        assertArrayEquals(new byte[] {1, 2, 3}, bytes);
                    });
        }

        assertArrayEquals(new byte[3], callbackCopy.get());
    }

    @Test
    void heapProviderWipesCallbackCopyWhenCallbackThrows() {
        AtomicReference<byte[]> callbackCopy = new AtomicReference<>();
        try (SecretMemory memory = SecretMemoryProvider.heap().protect(new byte[] {1, 2, 3})) {
            assertThrows(
                    IllegalStateException.class,
                    () ->
                            memory.copyBytes(
                                    bytes -> {
                                        callbackCopy.set(bytes);
                                        throw new IllegalStateException("failed callback");
                                    }));
        }

        assertArrayEquals(new byte[3], callbackCopy.get());
    }

    @Test
    void heapProviderCloseWaitsForInFlightCallback() throws Exception {
        SecretMemory memory = SecretMemoryProvider.heap().protect(new byte[] {1, 2, 3});
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
            assertThrows(
                    SecretDestroyedException.class,
                    () -> memory.copyBytes(bytes -> fail("closed memory should not be readable")));
        } finally {
            release.countDown();
            memory.close();
            executor.shutdownNow();
        }
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
