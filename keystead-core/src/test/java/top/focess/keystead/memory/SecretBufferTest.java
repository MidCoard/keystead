package top.focess.keystead.memory;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class SecretBufferTest {

    @Test
    void toStringIsAlwaysRedacted() {
        try (SecretBuffer buffer =
                SecretBuffer.fromChars(new char[] {'s', 'e', 'c', 'r', 'e', 't'})) {
            assertEquals("[REDACTED SECRET]", buffer.toString());
        }
    }

    @Test
    void closeWipesOwnedCharactersAndRejectsFutureAccess() {
        SecretBuffer buffer = SecretBuffer.fromChars(new char[] {'p', 'a', 's', 's'});

        buffer.close();

        assertTrue(buffer.isClosed());
        assertThrows(
                SecretDestroyedException.class,
                () -> buffer.copyChars(chars -> fail("closed buffer should not be readable")));
        assertArrayEquals(new byte[] {0, 0, 0, 0}, rawBytes(buffer));
    }

    @Test
    void inputArrayIsCopiedSoCallerCanWipeItsOwnData() {
        char[] input = new char[] {'p', 'a', 's', 's'};
        try (SecretBuffer buffer = SecretBuffer.fromChars(input)) {
            Arrays.fill(input, '\0');

            AtomicReference<char[]> seen = new AtomicReference<>();
            buffer.copyChars(chars -> seen.set(chars.clone()));

            assertArrayEquals(new char[] {'p', 'a', 's', 's'}, seen.get());
        }
    }

    @Test
    void callbackReceivesTemporaryCopyForBytes() {
        try (SecretBuffer buffer =
                SecretBuffer.fromUtf8("token".getBytes(StandardCharsets.UTF_8))) {
            AtomicReference<byte[]> seen = new AtomicReference<>();

            buffer.copyBytes(
                    bytes -> {
                        seen.set(bytes.clone());
                        bytes[0] = 'X';
                    });

            assertArrayEquals("token".getBytes(StandardCharsets.UTF_8), seen.get());
            buffer.copyBytes(
                    bytes -> assertArrayEquals("token".getBytes(StandardCharsets.UTF_8), bytes));
        }
    }

    @Test
    void injectedProviderIsUsedWithoutTakingOwnershipOfCallerInputs() {
        AtomicInteger calls = new AtomicInteger();
        SecretMemoryProvider provider =
                value -> {
                    calls.incrementAndGet();
                    return SecretMemoryProvider.heap().protect(value);
                };
        byte[] input = "secret".getBytes(StandardCharsets.UTF_8);
        char[] chars = new char[] {'p', 'a', 's', 's'};

        try (SecretBuffer buffer = SecretBuffer.fromUtf8(input, provider);
                SecretBuffer charBuffer = SecretBuffer.fromChars(chars, provider)) {
            Arrays.fill(input, (byte) 0);
            Arrays.fill(chars, '\0');

            assertEquals(2, calls.get());
            buffer.copyBytes(
                    bytes -> assertArrayEquals("secret".getBytes(StandardCharsets.UTF_8), bytes));
            charBuffer.copyChars(
                    copiedChars -> assertArrayEquals(new char[] {'p', 'a', 's', 's'}, copiedChars));
        }
    }

    @Test
    void closeWaitsForInFlightCallback() throws Exception {
        SecretBuffer buffer = SecretBuffer.fromUtf8("secret".getBytes(StandardCharsets.UTF_8));
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch closeStarted = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<?> access =
                    executor.submit(
                            () ->
                                    buffer.copyBytes(
                                            bytes -> {
                                                entered.countDown();
                                                await(release);
                                                assertArrayEquals(
                                                        "secret".getBytes(StandardCharsets.UTF_8),
                                                        bytes);
                                            }));
            assertTrue(entered.await(2, TimeUnit.SECONDS));

            Future<?> close =
                    executor.submit(
                            () -> {
                                closeStarted.countDown();
                                buffer.close();
                            });
            assertTrue(closeStarted.await(2, TimeUnit.SECONDS));
            assertThrows(TimeoutException.class, () -> close.get(100, TimeUnit.MILLISECONDS));

            release.countDown();
            access.get(2, TimeUnit.SECONDS);
            close.get(2, TimeUnit.SECONDS);
            assertThrows(
                    SecretDestroyedException.class,
                    () -> buffer.copyBytes(bytes -> fail("closed buffer should not be readable")));
        } finally {
            release.countDown();
            buffer.close();
            executor.shutdownNow();
        }
    }

    private static byte[] rawBytes(SecretBuffer buffer) {
        try {
            Field memoryField = SecretBuffer.class.getDeclaredField("memory");
            memoryField.setAccessible(true);
            Object memory = memoryField.get(buffer);
            Field bytesField = memory.getClass().getDeclaredField("bytes");
            bytesField.setAccessible(true);
            return ((byte[]) bytesField.get(memory)).clone();
        } catch (ReflectiveOperationException e) {
            throw new AssertionError(e);
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
