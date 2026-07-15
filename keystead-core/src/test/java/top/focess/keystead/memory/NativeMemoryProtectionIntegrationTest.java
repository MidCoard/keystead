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
 * Real local integration tests for the native locked-memory lifecycle and capability inspection,
 * enabled per OS. Windows runs locally; Linux and macOS run in the CI matrix.
 */
class NativeMemoryProtectionIntegrationTest {

    @Test
    @EnabledOnOs(OS.WINDOWS)
    void realWindowsLifecycleProtectsCopiesWipesAndReleases() {
        assertLifecycleRoundTrips();
    }

    @Test
    @EnabledOnOs(OS.LINUX)
    void realLinuxLifecycleProtectsCopiesWipesAndReleases() {
        assertLifecycleRoundTrips();
    }

    @Test
    @EnabledOnOs(OS.MAC)
    void realMacOsLifecycleProtectsCopiesWipesAndReleases() {
        assertLifecycleRoundTrips();
    }

    @Test
    @EnabledOnOs(OS.WINDOWS)
    void realWindowsInspectReportsVerifiedCapabilitiesWithoutRetainingThePage() {
        assertInspectReportsVerified(NativeProtectionStatus.NOT_APPLICABLE);
    }

    @Test
    @EnabledOnOs(OS.LINUX)
    void realLinuxInspectReportsVerifiedCapabilitiesIncludingDumpExclusion() {
        assertInspectReportsVerified(NativeProtectionStatus.VERIFIED);
    }

    @Test
    @EnabledOnOs(OS.MAC)
    void realMacOsInspectReportsVerifiedCapabilitiesWithoutDumpExclusion() {
        assertInspectReportsVerified(NativeProtectionStatus.NOT_APPLICABLE);
    }

    private static void assertLifecycleRoundTrips() {
        byte[] secret = new byte[] {1, 2, 3, 4, 5};
        SecretMemory memory = SecretMemoryProvider.nativeLocked().protect(secret);
        try {
            assertEquals(5, memory.length());
            assertFalse(memory.isClosed());
            memory.copyBytes(bytes -> assertArrayEquals(secret, bytes));
            memory.copyBytes(bytes -> assertArrayEquals(secret, bytes));
        } finally {
            memory.close();
        }
        assertTrue(memory.isClosed());
        assertThrows(SecretDestroyedException.class, memory::length);

        SecretMemory zero = SecretMemoryProvider.nativeLocked().protect(new byte[0]);
        try {
            assertEquals(0, zero.length());
            zero.copyBytes(bytes -> assertEquals(0, bytes.length));
        } finally {
            zero.close();
        }

        byte[] multiPage = new byte[8192];
        for (int i = 0; i < multiPage.length; i++) {
            multiPage[i] = (byte) (i % 251);
        }
        SecretMemory paged = SecretMemoryProvider.nativeLocked().protect(multiPage);
        try {
            assertEquals(8192, paged.length());
            paged.copyBytes(bytes -> assertArrayEquals(multiPage, bytes));
        } finally {
            paged.close();
        }
    }

    private static void assertInspectReportsVerified(NativeProtectionStatus dumpExclusionStatus) {
        NativeMemoryProtectionReport report = NativeMemoryProtection.inspect();

        assertEquals(NativeProtectionControl.values().length, report.results().size());
        assertEquals(
                NativeProtectionStatus.VERIFIED,
                report.result(NativeProtectionControl.PLATFORM).status());
        assertEquals(
                NativeProtectionStatus.VERIFIED,
                report.result(NativeProtectionControl.NATIVE_ACCESS).status());
        assertEquals(
                NativeProtectionStatus.VERIFIED,
                report.result(NativeProtectionControl.ABI_LAYOUTS).status());
        assertEquals(
                NativeProtectionStatus.VERIFIED,
                report.result(NativeProtectionControl.SYMBOLS).status());
        assertEquals(
                NativeProtectionStatus.VERIFIED,
                report.result(NativeProtectionControl.ALLOCATION).status());
        assertEquals(
                NativeProtectionStatus.VERIFIED,
                report.result(NativeProtectionControl.PAGE_LOCK).status());
        assertEquals(
                dumpExclusionStatus,
                report.result(NativeProtectionControl.DUMP_EXCLUSION).status());
        assertEquals(
                NativeProtectionStatus.VERIFIED,
                report.result(NativeProtectionControl.WIPE).status());
        assertEquals(
                NativeProtectionStatus.VERIFIED,
                report.result(NativeProtectionControl.PAGE_UNLOCK).status());
        assertEquals(
                NativeProtectionStatus.VERIFIED,
                report.result(NativeProtectionControl.RELEASE).status());
    }
}
