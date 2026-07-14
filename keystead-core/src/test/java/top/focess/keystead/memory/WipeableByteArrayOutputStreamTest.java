package top.focess.keystead.memory;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class WipeableByteArrayOutputStreamTest {

    @Test
    void closeWipesEntireInheritedBackingArray() throws Exception {
        InspectableWipeableByteArrayOutputStream output =
                new InspectableWipeableByteArrayOutputStream();
        output.write("private-key".getBytes(StandardCharsets.UTF_8));
        byte[] backing = output.backingArray();
        assertTrue(backing.length > output.size());

        output.close();

        assertArrayEquals(new byte[backing.length], backing);
        assertEquals(0, output.size());
    }

    @Test
    void createsSecretBufferWithoutRetainingTemporaryCopy() {
        try (WipeableByteArrayOutputStream output = new WipeableByteArrayOutputStream()) {
            output.writeBytes("private-key".getBytes(StandardCharsets.UTF_8));

            try (SecretBuffer secret = output.toSecretBuffer(SecretMemoryProvider.heap())) {
                secret.copyBytes(
                        bytes ->
                                assertArrayEquals(
                                        "private-key".getBytes(StandardCharsets.UTF_8), bytes));
            }
        }
    }

    @Test
    void wipesTemporaryCopyWhenProviderThrowsThrowable() {
        AtomicReference<byte[]> received = new AtomicReference<>();
        SecretMemoryProvider provider =
                value -> {
                    received.set(value);
                    throw new AssertionError("provider failure");
                };
        try (WipeableByteArrayOutputStream output = new WipeableByteArrayOutputStream()) {
            output.writeBytes("private-key".getBytes(StandardCharsets.UTF_8));

            assertThrows(AssertionError.class, () -> output.toSecretBuffer(provider));

            assertArrayEquals(new byte["private-key".length()], received.get());
        }
    }

    private static final class InspectableWipeableByteArrayOutputStream
            extends WipeableByteArrayOutputStream {

        private byte[] backingArray() {
            return buf;
        }
    }
}
