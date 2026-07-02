package top.focess.keystead.memory;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
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

    private static byte[] rawBytes(SecretBuffer buffer) {
        try {
            Field field = SecretBuffer.class.getDeclaredField("bytes");
            field.setAccessible(true);
            return ((byte[]) field.get(buffer)).clone();
        } catch (ReflectiveOperationException e) {
            throw new AssertionError(e);
        }
    }
}
