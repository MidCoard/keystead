package top.focess.keystead.memory;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

/**
 * Real local Windows integration test for the native locked-memory lifecycle. Allocates a real
 * Kernel32 mapping, locks it, copies bytes in and out, wipes, unlocks, and releases.
 */
@EnabledOnOs(OS.WINDOWS)
class NativeMemoryProtectionIntegrationTest {

    @Test
    void realWindowsLifecycleProtectsCopiesWipesAndReleases() {
        SecretMemory memory =
                SecretMemoryProvider.nativeLocked().protect(new byte[] {1, 2, 3, 4, 5});
        try {
            assertEquals(5, memory.length());
            assertFalse(memory.isClosed());
            memory.copyBytes(bytes -> assertArrayEquals(new byte[] {1, 2, 3, 4, 5}, bytes));
            memory.copyBytes(bytes -> assertArrayEquals(new byte[] {1, 2, 3, 4, 5}, bytes));
        } finally {
            memory.close();
        }
        assertTrue(memory.isClosed());
        assertThrows(SecretDestroyedException.class, memory::length);
    }

    @Test
    void realWindowsZeroLengthSecretOwnsOneProtectedPage() {
        SecretMemory memory = SecretMemoryProvider.nativeLocked().protect(new byte[0]);
        try {
            assertEquals(0, memory.length());
            memory.copyBytes(bytes -> assertEquals(0, bytes.length));
        } finally {
            memory.close();
        }
    }

    @Test
    void realWindowsMultiPageSecretRoundTrips() {
        byte[] secret = new byte[8192];
        for (int i = 0; i < secret.length; i++) {
            secret[i] = (byte) (i % 251);
        }
        SecretMemory memory = SecretMemoryProvider.nativeLocked().protect(secret);
        try {
            assertEquals(8192, memory.length());
            memory.copyBytes(bytes -> assertArrayEquals(secret, bytes));
        } finally {
            memory.close();
        }
    }
}
